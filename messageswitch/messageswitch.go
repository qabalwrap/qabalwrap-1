package messageswitch

import (
	"context"
	"log"
	"sync"
	"time"

	md5digest "github.com/go-marshaltemabu/go-md5digest"
	"google.golang.org/protobuf/proto"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

const localServiceRefContentIdent = qabalwrap.ContentIdentLocalServiceRef

// MessageSwitch provide message switching services.
type MessageSwitch struct {
	qabalwrap.ServiceBase

	localServiceRef *ServiceReference
	primarySwitch   bool

	stateStore *qabalwrap.StateStore

	diagnosisEmitter *qabalwrap.DiagnosisEmitter

	tlsCertProvider qw1tlscert.Provider
	crossBar        crossBar
	precomputedKeys precomputedKeyCache

	localServices      []qabalwrap.ServiceProvider
	messageDispatchers []*messageDispatcher

	notifyPeerKnownServiceIdents  chan *knownServiceIdentsNotify
	notifyRelayLinkEstablished    chan *relayLinkEstablishNotify
	allocateServiceIdentsRequests chan *serviceReferenceRequest
	rootCertificateRequests       chan *rootCertRequest
	rootCertificateAssignment     chan *rootCertAssignment
	hostCertificateRequests       chan *hostCertRequest
	hostCertificateAssignments    chan *hostCertAssignment
}

// NewMessageSwitch create new instance of MessageSwitch.
func NewMessageSwitch(
	spanEmitter *qabalwrap.TraceEmitter,
	stateStore *qabalwrap.StateStore,
	diag *qabalwrap.DiagnosisEmitter,
	textIdent, dnCountry, dnOrganization string,
	primarySwitch bool) (s *MessageSwitch, err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(qabalwrap.ServiceInstanceIdentifier(textIdent), "new-message-switch")
	aux := &MessageSwitch{
		ServiceBase: qabalwrap.ServiceBase{
			ServiceInstanceIdent: qabalwrap.ServiceInstanceIdentifier(textIdent),
		},
		primarySwitch:                 primarySwitch,
		stateStore:                    stateStore,
		diagnosisEmitter:              diag,
		notifyPeerKnownServiceIdents:  make(chan *knownServiceIdentsNotify, 2),
		notifyRelayLinkEstablished:    make(chan *relayLinkEstablishNotify, 2),
		allocateServiceIdentsRequests: make(chan *serviceReferenceRequest, 2),
		rootCertificateRequests:       make(chan *rootCertRequest, 2),
		rootCertificateAssignment:     make(chan *rootCertAssignment, 1),
		hostCertificateRequests:       make(chan *hostCertRequest, 8),
		hostCertificateAssignments:    make(chan *hostCertAssignment, 8),
	}
	if err = aux.tlsCertProvider.Init(qabalwrap.ServiceInstanceIdentifier(textIdent)+"-tlsprovider",
		dnCountry, dnOrganization, stateStore, primarySwitch); nil != err {
		spanEmitter.FinishSpanFailedLogf("(NewMessageSwitch) init TLS certificate provider failed: %v", err)
		return
	}
	if err = aux.crossBar.Init(spanEmitter, stateStore, textIdent, aux, primarySwitch); nil != err {
		spanEmitter.FinishSpanFailedLogf("(NewMessageSwitch) init crossbar failed: %v", err)
		return
	}
	if conn := aux.crossBar.findServiceConnectByTextIdent(textIdent); conn == nil {
		spanEmitter.FinishSpanFailedLogf("(NewMessageSwitch) not reach message switch service: %s", textIdent)
		err = ErrNotHavingMessageSwitchServiceRecord
		return
	} else {
		aux.localServiceRef = &conn.ServiceReference
	}
	aux.precomputedKeys.init()
	s = aux
	spanEmitter.FinishSpanSuccessWithoutMessage()
	return
}

func (s *MessageSwitch) refreshLocalServiceRef(spanEmitter *qabalwrap.TraceEmitter) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-refresh-local-service-ref")
	if conn := s.crossBar.findServiceConnectByTextIdent(s.localServiceRef.TextIdent); conn == nil {
		spanEmitter.FinishSpanFailedLogf("failed: (MessageSwitch::refreshLocalServiceRef) not reach message switch service: %s", s.localServiceRef.TextIdent)
		err = ErrNotHavingMessageSwitchServiceRecord
		return
	} else if (s.localServiceRef.SerialIdent != conn.SerialIdent) || (s.localServiceRef.UniqueIdent != conn.UniqueIdent) {
		spanEmitter.EventWarning("(MessageSwitch::refreshLocalServiceRef) modify local service reference: %d => %d, %s => %s.",
			s.localServiceRef.SerialIdent, conn.SerialIdent, s.localServiceRef.UniqueIdent.String(), conn.UniqueIdent.String())
		s.localServiceRef = &conn.ServiceReference
	}
	var onDiskLocalServiceRef ServiceReference
	ok, err := s.stateStore.Unmarshal(localServiceRefContentIdent, &onDiskLocalServiceRef)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::refreshLocalServiceRef) cannot unpack local service reference from disk: %v", err)
		return
	}
	if ok && (onDiskLocalServiceRef.SerialIdent == s.localServiceRef.SerialIdent) && (onDiskLocalServiceRef.UniqueIdent == s.localServiceRef.UniqueIdent) && (onDiskLocalServiceRef.TextIdent == s.localServiceRef.TextIdent) {
		spanEmitter.FinishSpanSuccess("ident not change")
		return
	}
	if err = s.stateStore.Marshal(localServiceRefContentIdent, s.localServiceRef); nil != err {
		spanEmitter.FinishSpanFailedLogf("updating local service reference: result=%v", err)
	} else {
		spanEmitter.FinishSpanSuccess("updated local service reference")
	}
	return
}

// forwardClearEnvelopedMessage send message to target service.
// Invoke at operating stage by local services.
func (s *MessageSwitch) forwardClearEnvelopedMessage(
	spanEmitter *qabalwrap.TraceEmitter, msg *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan(s.ServiceInstanceIdent, "switch-forward-clear-message", "src=%d, dst=%d", msg.SourceServiceIdent, msg.DestinationServiceIdent)
	srcServiceConn, destServiceConn, err := s.crossBar.getTransmitionConnects(msg.SourceServiceIdent, msg.DestinationServiceIdent)
	if nil != err {
		spanEmitter.FinishSpanFailed("cannot have transmition connects: %v", err)
		return
	}
	if hopCount, _ := destServiceConn.linkHopStat(); hopCount == 0 {
		if err = destServiceConn.serviceProvider.ReceiveMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpanFailed("direct forward: %v", err)
		} else {
			spanEmitter.FinishSpanSuccess("direct forward")
		}
	} else if hopCount < maxLinkHopCount {
		precompSharedKey := s.precomputedKeys.getEncryptSharedKey(srcServiceConn, destServiceConn)
		if err = msg.Encrypt(precompSharedKey); nil != err {
			spanEmitter.FinishSpanFailed("encrypt for forwarding to network: %v", err)
		} else if err = destServiceConn.emitMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpanFailed("forward to network: %v", err)
		} else {
			spanEmitter.FinishSpanSuccess("forward to network")
		}
	} else {
		err = ErrRelayLinksUnreachable(msg.DestinationServiceIdent)
		spanEmitter.FinishSpanFailed("cannot have relay link: destination-service-ident=%d")
	}
	return
}

// forwardEncryptedEnvelopedMessage send message to target service.
// Invoke at operating stage by relay providers.
func (s *MessageSwitch) forwardEncryptedEnvelopedMessage(spanEmitter *qabalwrap.TraceEmitter, msg *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan(s.ServiceInstanceIdent, "switch-forward-encrypted-message", "src=%d, dst=%d", msg.SourceServiceIdent, msg.DestinationServiceIdent)
	srcServiceConn, destServiceConn, err := s.crossBar.getTransmitionConnects(msg.SourceServiceIdent, msg.DestinationServiceIdent)
	if nil != err {
		spanEmitter.FinishSpanFailed("cannot have transmition connects: %v", err)
		return
	}
	if hopCount, _ := destServiceConn.linkHopStat(); hopCount == 0 {
		precompSharedKey := s.precomputedKeys.getDecryptSharedKey(srcServiceConn, destServiceConn)
		if err = msg.Decrypt(precompSharedKey); nil != err {
			spanEmitter.FinishSpanFailed("cannot decrypt: %v", err)
			return
		} else if err = destServiceConn.serviceProvider.ReceiveMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpanFailed("local forward: %v", err)
		} else {
			spanEmitter.FinishSpanSuccess("local forward")
		}
	} else if hopCount < maxLinkHopCount {
		if err = destServiceConn.emitMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpanFailed("forward to network: %v", err)
		} else {
			spanEmitter.FinishSpanSuccess("forward to network")
		}
	} else {
		err = ErrRelayLinksUnreachable(msg.DestinationServiceIdent)
		spanEmitter.FinishSpanFailed("cannot have relay link: destination-service-ident=%d")
	}
	return
}

func (s *MessageSwitch) buildKnownServiceIdentsMessage(spanEmitter *qabalwrap.TraceEmitter) (msg *qabalwrap.EnvelopedMessage, digest md5digest.MD5Digest, err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-build-known-service-idents-message")
	knownServiceIdents, err := s.crossBar.makeKnownServiceIdentsSnapshot(spanEmitter, s.localServiceRef.SerialIdent)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::buildKnownServiceIdentsMessage) cannot have known service idents: %v", err)
		return
	}
	buf, err := proto.Marshal(knownServiceIdents)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::buildKnownServiceIdentsMessage) marshal known service idents failed (step-1): %v", err)
		return
	}
	digest.SumBytes(buf)
	knownServiceIdents.GenerationTimestamp = time.Now().UnixNano()
	if buf, err = proto.Marshal(knownServiceIdents); nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::buildKnownServiceIdentsMessage) marshal known service idents failed (step-2): %v", err)
		return
	}
	msg = qabalwrap.NewClearEnvelopedMessage(
		qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent,
		qabalwrap.MessageContentKnownServiceIdents, buf)
	spanEmitter.FinishSpanSuccessWithoutMessage()
	return
}

func (s *MessageSwitch) nonblockingRelayPeerMessage(
	spanEmitter *qabalwrap.TraceEmitter, relayIndex int, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpan(s.ServiceInstanceIdent, "switch-nonblock-relay-peer-msg", "relay-index=%d", relayIndex)
	if (relayIndex < 0) || (relayIndex >= len(s.messageDispatchers)) {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::nonblockingRelayPeerMessage) invalid relay index: %d", relayIndex)
		return
	}
	if !s.messageDispatchers[relayIndex].relayInst.NonblockingEmitMessage(spanEmitter, m) {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::nonblockingRelayPeerMessage) non-blocking message dispatch is not successful: relay-index=%d", relayIndex)
	} else {
		spanEmitter.FinishSpanSuccessWithoutMessage()
	}
}

func (s *MessageSwitch) nonblockingRelayPeerBroadcast(
	spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-nonblock-relay-peer-broadcast")
	defer spanEmitter.FinishSpanSuccessWithoutMessage()
	for _, msgDispatcher := range s.messageDispatchers {
		if !msgDispatcher.relayInst.NonblockingEmitMessage(spanEmitter, m) {
			spanEmitter.EventWarning("(MessageSwitch::nonblockingRelayPeerBroadcast) non-blocking message dispatch is not successful: relay-index=%d", msgDispatcher.relayIndex)
		}
	}
}

func (s *MessageSwitch) checkCrossBarServiceConnectChanged(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-check-crossbar-service-connect-changed")
	if s.crossBar.getCurrentKnownServiceModifyTimestamp() == 0 {
		spanEmitter.FinishSpanSuccess("empty modify timestamp")
		return
	}
	spanEmitter.EventInfo("(MessageSwitch::checkCrossBarServiceConnectChanged) service reference modified.")
	if err := s.crossBar.save(s.stateStore); nil != err {
		spanEmitter.EventError("(MessageSwitch::checkCrossBarServiceConnectChanged) saving known service reference failed: %v", err)
	}
	connects := s.crossBar.makeServiceConnectsSnapshot()
	for connIndex, connInst := range connects {
		if connInst == nil {
			spanEmitter.EventInfo("(MessageSwitch::checkCrossBarServiceConnectChanged) empty service connection: index=%d.", connIndex)
		}
		connInst.setMessageSender(spanEmitter, s)
	}
	if err := s.refreshLocalServiceRef(spanEmitter); nil != err {
		spanEmitter.EventError("(MessageSwitch::checkCrossBarServiceConnectChanged) update local service reference failed: %v", err)
	}
	spanEmitter.FinishSpanSuccessWithoutMessage()
}

// emitRelayHeartbeat send heartbeat to relaies and collect losted relaies.
// Invoked by maintenance routine.
func (s *MessageSwitch) emitRelayHeartbeat(spanEmitter *qabalwrap.TraceEmitter) (linkLostRelay []int) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-emit-relay-heartbeat")
	for _, dispatcher := range s.messageDispatchers {
		if dispatcher.shouldEmitHeartbeat() {
			dispatcher.emitHeartbeatPing(spanEmitter)
		}
		if !dispatcher.checkLinkTrafficStatus(spanEmitter) {
			linkLostRelay = append(linkLostRelay, dispatcher.relayIndex)
			spanEmitter.EventWarning("losted relay: %d", dispatcher.relayIndex)
		}
	}
	spanEmitter.FinishSpanSuccessWithoutMessage()
	return
}

func (s *MessageSwitch) emitAllocateServiceIdentsRequest(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-emit-allocate-service-ident-req")
	if s.primarySwitch {
		spanEmitter.FinishSpanSuccess("(MessageSwitch::requestServiceSerialAssignment) skip emitAllocateServiceIdentsRequest on primary switch.")
		return
	}
	reqMsg, err := s.crossBar.makeAllocateServiceIdentsRequest()
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::requestServiceSerialAssignment) cannot make AllocateServiceIdentsRequest: %v", err)
		return
	}
	if reqMsg == nil {
		spanEmitter.FinishSpanSuccess("empty allocate request")
		return
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.MessageContentAllocateServiceIdentsRequest, reqMsg)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::requestServiceSerialAssignment) cannot create enveloped message: %v", err)
		return
	}
	primaryLink := s.crossBar.getServiceConnectBySerial(qabalwrap.PrimaryMessageSwitchServiceIdent)
	if (primaryLink == nil) || (!primaryLink.linkAvailable()) {
		spanEmitter.EventInfo("(MessageSwitch::requestServiceSerialAssignment) cannot reach primary switch.")
		primaryLink = nil
	}
	if primaryLink != nil {
		if err = primaryLink.emitMessage(spanEmitter, m); nil != err {
			spanEmitter.FinishSpanFailedLogf("(MessageSwitch::requestServiceSerialAssignment) cannot emit enveloped message: %v", err)
		} else {
			spanEmitter.FinishSpanSuccess("emitted allocate request for %d services with primary link", len(reqMsg.ServiceIdents))
		}
	} else {
		for relayIndex, relayInst := range s.crossBar.relayProviders {
			emitSuccess := relayInst.NonblockingEmitMessage(spanEmitter, m)
			spanEmitter.EventInfo("(MessageSwitch::requestServiceSerialAssignment) emit with relay (index=%d): success=%v.", relayIndex, emitSuccess)
		}
		spanEmitter.FinishSpanSuccess("emitted allocate request for %d services with relies", len(reqMsg.ServiceIdents))
	}
}

func (s *MessageSwitch) emitRootCertificateRequest(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-emit-root-cert-req")
	if s.tlsCertProvider.HaveRootCertificate() {
		spanEmitter.FinishSpanSuccess("(MessageSwitch::emitRootCertificateRequest) skip emitRootCertificateRequest as root certificate existed.")
		return
	}
	if primaryLink := s.crossBar.getServiceConnectBySerial(qabalwrap.PrimaryMessageSwitchServiceIdent); (primaryLink == nil) || (!primaryLink.linkAvailable()) {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::emitRootCertificateRequest) cannot reach primary switch.")
		return
	}
	reqMsg := &qbw1grpcgen.RootCertificateRequest{
		Timestamp: time.Now().Unix(),
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(
		s.localServiceRef.SerialIdent, qabalwrap.PrimaryMessageSwitchServiceIdent,
		qabalwrap.MessageContentRootCertificateRequest, reqMsg)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::emitRootCertificateRequest) cannot create enveloped message: %v", err)
		return
	}
	if err = s.forwardClearEnvelopedMessage(spanEmitter, m); nil != err {
		spanEmitter.FinishSpanFailedLogf("(MessageSwitch::emitRootCertificateRequest) cannot emit enveloped message: %v", err)
	} else {
		spanEmitter.FinishSpanSuccess("(MessageSwitch::emitRootCertificateRequest) sent RootCertificateRequest.")
	}
}

func (s *MessageSwitch) emitHostCertificateRequests(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-emit-host-cert-reqs")
	hostNames := s.tlsCertProvider.CollectSelfSignedHosts(spanEmitter)
	if len(hostNames) == 0 {
		spanEmitter.FinishSpanSuccess("empty host names")
		return
	}
	for _, hostN := range hostNames {
		reqMsg := &qbw1grpcgen.HostCertificateRequest{
			HostDNSName: hostN,
		}
		m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(
			s.localServiceRef.SerialIdent, qabalwrap.PrimaryMessageSwitchServiceIdent,
			qabalwrap.MessageContentHostCertificateRequest, reqMsg)
		if nil != err {
			spanEmitter.FinishSpanFailedLogf("(MessageSwitch::emitHostCertificateRequests) cannot create enveloped message: %v", err)
			return
		}
		if err = s.forwardClearEnvelopedMessage(spanEmitter, m); nil != err {
			spanEmitter.EventError("(MessageSwitch::emitHostCertificateRequests) cannot emit enveloped message: %v", err)
		} else {
			spanEmitter.EventInfo("(MessageSwitch::emitHostCertificateRequests) sent host certificate request: [%s].", hostN)
		}
	}
	spanEmitter.FinishSpanSuccessWithoutMessage()
}

func (s *MessageSwitch) maintenanceWorks(ctx context.Context, waitGroup *sync.WaitGroup) {
	spanEmitter := s.diagnosisEmitter.StartTraceWithoutMessage(s.ServiceInstanceIdent, "switch-maintenance-work:init")
	defer waitGroup.Done()
	hndKnownServiceIdentsNotify, err := newKnownServiceIdentsNotifyHandler(spanEmitter, s)
	if nil != err {
		log.Printf("WARN: (MessageSwitch::maintenanceWorks) cannot build known service idents: %v", err)
	}
	ticker := time.NewTicker(time.Minute * 2)
	defer ticker.Stop()
	s.emitAllocateServiceIdentsRequest(spanEmitter)
	lostedRelayIndexes := newRelayIndexSet()
	spanEmitter.FinishSpanSuccessWithoutMessage()
	running := true
	for running {
		spanEmitter = s.diagnosisEmitter.StartTrace(s.ServiceInstanceIdent, "switch-maintenance-work", "iteration %v", time.Now())
		s.checkCrossBarServiceConnectChanged(spanEmitter)
		select {
		case notice := <-s.notifyPeerKnownServiceIdents:
			hndKnownServiceIdentsNotify.handle(notice)
		case notice := <-s.notifyRelayLinkEstablished:
			hndKnownServiceIdentsNotify.emitCachedKnownServiceIdents(notice.spanEmitter, notice.relayIndex)
		case allocateServiceReq := <-s.allocateServiceIdentsRequests:
			handleAllocateServiceIdentsRequest(s, allocateServiceReq)
			hndKnownServiceIdentsNotify.checkChanges(allocateServiceReq.SpanEmitter)
		case rootCertReq := <-s.rootCertificateRequests:
			handleRootCertificateRequest(s, rootCertReq)
		case rootCertAssign := <-s.rootCertificateAssignment:
			handleRootCertificateAssignment(waitGroup, s, rootCertAssign)
		case hostCertReq := <-s.hostCertificateRequests:
			handleHostCertificateRequest(s, hostCertReq)
		case hostCertAssign := <-s.hostCertificateAssignments:
			handleHostCertificateAssignment(waitGroup, s, hostCertAssign)
		case <-ticker.C:
			spanEmitter.EventInfo("(MessageSwitch::maintenanceWorks) run tick routine.")
			lostedRelay := s.emitRelayHeartbeat(spanEmitter)
			s.crossBar.relayLinksLosted(spanEmitter, lostedRelay)
			for _, relayIdx := range lostedRelayIndexes.retain(lostedRelay) {
				hndKnownServiceIdentsNotify.emitCachedKnownServiceIdents(spanEmitter, relayIdx)
			}
			s.emitAllocateServiceIdentsRequest(spanEmitter)
			s.emitRootCertificateRequest(spanEmitter)
			s.emitHostCertificateRequests(spanEmitter)
		case <-ctx.Done():
			running = false
			spanEmitter.EventInfo("(MessageSwitch::maintenanceWorks) get stop notice.")
		}
		spanEmitter.FinishSpanSuccessWithoutMessage()
	}
	spanEmitter = s.diagnosisEmitter.StartTrace(s.ServiceInstanceIdent, "switch-maintenance-work", "(MessageSwitch::maintenanceWorks) leaving maintenance work loop.")
	s.checkCrossBarServiceConnectChanged(spanEmitter)
	spanEmitter.FinishSpanSuccess("(MessageSwitch::maintenanceWorks) maintenance work loop stopped.")
}

// Setup prepare provider for operation.
// Should only invoke at maintenance thread in setup stage.
func (s *MessageSwitch) Setup(
	serviceInstIdent qabalwrap.ServiceInstanceIdentifier,
	diagnosisEmitter *qabalwrap.DiagnosisEmitter,
	certProvider qabalwrap.CertificateProvider) (err error) {
	s.ServiceInstanceIdent = serviceInstIdent
	return
}

func (s *MessageSwitch) postSetup(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-post-setup")
	defer spanEmitter.FinishSpanSuccessWithoutMessage()
	relayProviders := s.crossBar.relayProviders
	s.messageDispatchers = make([]*messageDispatcher, len(relayProviders))
	for relayIndex, relayInst := range relayProviders {
		msgDispatcher := newMessageDispatcher(relayIndex, relayInst, s)
		s.messageDispatchers[relayIndex] = msgDispatcher
		relayInst.SetMessageDispatcher(spanEmitter, msgDispatcher)
		spanEmitter.EventInfo("connect relay provider instance (index=%d) with message dispatcher",
			relayIndex)
	}
	connects := s.crossBar.makeServiceConnectsSnapshot()
	for connIndex, connInst := range connects {
		if connInst == nil {
			spanEmitter.EventInfo("(MessageSwitch::postSetup) empty service connection: index=%d.", connIndex)
		}
		connInst.setMessageSender(spanEmitter, s)
	}
}

// AddServiceProvider associate given service provider into message switch instance.
// Must only invoke at setup stage.
func (s *MessageSwitch) AddServiceProvider(textIdent string, serviceProvider qabalwrap.ServiceProvider) (err error) {
	if err = s.crossBar.attachServiceProvider(textIdent, serviceProvider); nil != err {
		return
	}
	if err = serviceProvider.Setup(
		qabalwrap.ServiceInstanceIdentifier(textIdent),
		s.diagnosisEmitter,
		&s.tlsCertProvider); nil != err {
		return
	}
	s.localServices = append(s.localServices, serviceProvider)
	return
}

func (s *MessageSwitch) Start(ctx context.Context, waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter) (err error) {
	if spanEmitter == nil {
		spanEmitter = s.diagnosisEmitter.StartTraceWithoutMessage(s.ServiceInstanceIdent, "message-switch-start")
	} else {
		spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "message-switch-start")
	}
	if s.primarySwitch {
		s.crossBar.assignServiceSerialIdents(spanEmitter)
	}
	s.crossBar.postSetup(spanEmitter)
	s.postSetup(spanEmitter)
	if err = s.tlsCertProvider.PostSetup(waitGroup, spanEmitter); nil != err {
		spanEmitter.EventError("cannot perform post setup of TLS certificate provider: %v", err)
	}
	waitGroup.Add(1)
	go s.maintenanceWorks(ctx, waitGroup)
	for _, svr := range s.localServices {
		if err = svr.Start(ctx, waitGroup, spanEmitter); nil != err {
			s.Stop()
			spanEmitter.FinishSpanFailed("cannot start service: %v", err)
			return
		}
	}
	spanEmitter.FinishSpanSuccessWithoutMessage()
	return
}

func (s *MessageSwitch) Stop() {
	for _, svr := range s.localServices {
		svr.Stop()
	}
	// stop maintenance thread
}

// ReceiveMessage deliver message into this instance of service provider.
// The message should decypted before pass into this method.
func (s *MessageSwitch) ReceiveMessage(spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "switch-receive-message")
	switch m.MessageContentType() {
	case qabalwrap.MessageContentAllocateServiceIdentsRequest:
		if err = queueAllocateServiceIdentsRequest(spanEmitter, s, m); nil != err {
			spanEmitter.EventError("(MessageSwitch::ReceiveMessage) queue allocate service ident request failed: %v", err)
		}
	case qabalwrap.MessageContentRootCertificateRequest:
		queueRootCertificateRequest(spanEmitter, s, m)
	case qabalwrap.MessageContentRootCertificateAssignment:
		if err = queueRootCertificateAssignment(spanEmitter, s, m); nil != err {
			spanEmitter.EventError("(MessageSwitch::ReceiveMessage) queue root cert assignment failed: %v", err)
		}
	case qabalwrap.MessageContentHostCertificateRequest:
		if err = queueHostCertificateRequest(spanEmitter, s, m); nil != err {
			spanEmitter.EventError("(MessageSwitch::ReceiveMessage) queue host cert request failed: %v", err)
		}
	case qabalwrap.MessageContentHostCertificateAssignment:
		if err = queueHostCertificateAssignment(spanEmitter, s, m); nil != err {
			spanEmitter.EventError("(MessageSwitch::ReceiveMessage) queue host cert assignment failed: %v", err)
		}
	default:
		spanEmitter.EventWarning("(MessageSwitch::ReceiveMessage) unprocess message from %d to %d [content-type=%d].",
			m.SourceServiceIdent, m.DestinationServiceIdent, m.MessageContentType())
	}
	if nil != err {
		spanEmitter.FinishSpanFailedErr(err)
	} else {
		spanEmitter.FinishSpanSuccessWithoutMessage()
	}
	return
}
