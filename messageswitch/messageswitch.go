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
	spanEmitter = spanEmitter.StartSpan("new-message-switch")
	aux := &MessageSwitch{
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
	if err = aux.tlsCertProvider.Init(dnCountry, dnOrganization, stateStore, primarySwitch); nil != err {
		spanEmitter.FinishSpanErrorf("(NewMessageSwitch) init TLS certificate provider failed: %v", err)
		return
	}
	if err = aux.crossBar.Init(spanEmitter, stateStore, textIdent, aux, primarySwitch); nil != err {
		spanEmitter.FinishSpanErrorf("(NewMessageSwitch) init crossbar failed: %v", err)
		return
	}
	if conn := aux.crossBar.findServiceConnectByTextIdent(textIdent); conn == nil {
		spanEmitter.FinishSpanErrorf("(NewMessageSwitch) not reach message switch service: %s", textIdent)
		err = ErrNotHavingMessageSwitchServiceRecord
		return
	} else {
		aux.localServiceRef = &conn.ServiceReference
	}
	aux.precomputedKeys.init()
	s = aux
	spanEmitter.FinishSpan("success")
	return
}

func (s *MessageSwitch) refreshLocalServiceRef(spanEmitter *qabalwrap.TraceEmitter) (err error) {
	spanEmitter = spanEmitter.StartSpan("switch-refresh-local-service-ref")
	if conn := s.crossBar.findServiceConnectByTextIdent(s.localServiceRef.TextIdent); conn == nil {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::refreshLocalServiceRef) not reach message switch service: %s", s.localServiceRef.TextIdent)
		err = ErrNotHavingMessageSwitchServiceRecord
		return
	} else if (s.localServiceRef.SerialIdent != conn.SerialIdent) || (s.localServiceRef.UniqueIdent != conn.UniqueIdent) {
		spanEmitter.EventWarningf("(MessageSwitch::refreshLocalServiceRef) modify local service reference: %d => %d, %s => %s.",
			s.localServiceRef.SerialIdent, conn.SerialIdent, s.localServiceRef.UniqueIdent.String(), conn.UniqueIdent.String())
		s.localServiceRef = &conn.ServiceReference
	}
	var onDiskLocalServiceRef ServiceReference
	ok, err := s.stateStore.Unmarshal(localServiceRefContentIdent, &onDiskLocalServiceRef)
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::refreshLocalServiceRef) cannot unpack local service reference from disk: %v", err)
		return
	}
	if ok && (onDiskLocalServiceRef.SerialIdent == s.localServiceRef.SerialIdent) && (onDiskLocalServiceRef.UniqueIdent == s.localServiceRef.UniqueIdent) && (onDiskLocalServiceRef.TextIdent == s.localServiceRef.TextIdent) {
		spanEmitter.FinishSpan("success: ident not change")
		return
	}
	if err = s.stateStore.Marshal(localServiceRefContentIdent, s.localServiceRef); nil != err {
		spanEmitter.FinishSpanErrorf("failed: updating local service reference: result=%v", err)
	} else {
		spanEmitter.FinishSpan("success: updated local service reference")
	}
	return
}

// forwardClearEnvelopedMessage send message to target service.
// Invoke at operating stage by local services.
func (s *MessageSwitch) forwardClearEnvelopedMessage(
	spanEmitter *qabalwrap.TraceEmitter, msg *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan("switch-forward-clear-message: src=%d, dst=%d", msg.SourceServiceIdent, msg.DestinationServiceIdent)
	srcServiceConn, destServiceConn, err := s.crossBar.getTransmitionConnects(msg.SourceServiceIdent, msg.DestinationServiceIdent)
	if nil != err {
		spanEmitter.FinishSpan("failed: cannot have transmition connects: %v", err)
		return
	}
	if hopCount, _ := destServiceConn.linkHopStat(); hopCount == 0 {
		if err = destServiceConn.serviceProvider.ReceiveMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpan("failed: direct forward: %v", err)
		} else {
			spanEmitter.FinishSpan("success: direct forward")
		}
	} else if hopCount < maxLinkHopCount {
		precompSharedKey := s.precomputedKeys.getEncryptSharedKey(srcServiceConn, destServiceConn)
		if err = msg.Encrypt(precompSharedKey); nil != err {
			spanEmitter.FinishSpan("failed: encrypt for forwarding to network: %v", err)
		} else if err = destServiceConn.emitMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpan("failed: forward to network: %v", err)
		} else {
			spanEmitter.FinishSpan("success: forward to network")
		}
	} else {
		err = ErrRelayLinksUnreachable(msg.DestinationServiceIdent)
		spanEmitter.FinishSpan("failed: cannot have relay link: destination-service-ident=%d")
	}
	return
}

// forwardEncryptedEnvelopedMessage send message to target service.
// Invoke at operating stage by relay providers.
func (s *MessageSwitch) forwardEncryptedEnvelopedMessage(spanEmitter *qabalwrap.TraceEmitter, msg *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan("switch-forward-encrypted-message: src=%d, dst=%d", msg.SourceServiceIdent, msg.DestinationServiceIdent)
	srcServiceConn, destServiceConn, err := s.crossBar.getTransmitionConnects(msg.SourceServiceIdent, msg.DestinationServiceIdent)
	if nil != err {
		spanEmitter.FinishSpan("failed: cannot have transmition connects: %v", err)
		return
	}
	if hopCount, _ := destServiceConn.linkHopStat(); hopCount == 0 {
		precompSharedKey := s.precomputedKeys.getDecryptSharedKey(srcServiceConn, destServiceConn)
		if err = msg.Decrypt(precompSharedKey); nil != err {
			spanEmitter.FinishSpan("failed: cannot decrypt: %v", err)
			return
		} else if err = destServiceConn.serviceProvider.ReceiveMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpan("failed: local forward: %v", err)
		} else {
			spanEmitter.FinishSpan("success: local forward")
		}
	} else if hopCount < maxLinkHopCount {
		if err = destServiceConn.emitMessage(spanEmitter, msg); nil != err {
			spanEmitter.FinishSpan("failed: forward to network: %v", err)
		} else {
			spanEmitter.FinishSpan("success: forward to network")
		}
	} else {
		err = ErrRelayLinksUnreachable(msg.DestinationServiceIdent)
		spanEmitter.FinishSpan("failed: cannot have relay link: destination-service-ident=%d")
	}
	return
}

func (s *MessageSwitch) buildKnownServiceIdentsMessage(spanEmitter *qabalwrap.TraceEmitter) (msg *qabalwrap.EnvelopedMessage, digest md5digest.MD5Digest, err error) {
	spanEmitter = spanEmitter.StartSpan("switch-build-known-service-idents-message")
	knownServiceIdents, err := s.crossBar.makeKnownServiceIdentsSnapshot(spanEmitter, s.localServiceRef.SerialIdent)
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::buildKnownServiceIdentsMessage) cannot have known service idents: %v", err)
		return
	}
	buf, err := proto.Marshal(knownServiceIdents)
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::buildKnownServiceIdentsMessage) marshal known service idents failed (step-1): %v", err)
		return
	}
	digest.SumBytes(buf)
	knownServiceIdents.GenerationTimestamp = time.Now().UnixNano()
	if buf, err = proto.Marshal(knownServiceIdents); nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::buildKnownServiceIdentsMessage) marshal known service idents failed (step-2): %v", err)
		return
	}
	msg = qabalwrap.NewClearEnvelopedMessage(
		qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent,
		qabalwrap.MessageContentKnownServiceIdents, buf)
	spanEmitter.FinishSpan("success")
	return
}

func (s *MessageSwitch) nonblockingRelayPeerMessage(
	spanEmitter *qabalwrap.TraceEmitter, relayIndex int, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpan("switch-nonblock-relay-peer-msg: relay-index=%d", relayIndex)
	if (relayIndex < 0) || (relayIndex >= len(s.messageDispatchers)) {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::nonblockingRelayPeerMessage) invalid relay index: %d", relayIndex)
		return
	}
	if !s.messageDispatchers[relayIndex].relayInst.NonblockingEmitMessage(spanEmitter, m) {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::nonblockingRelayPeerMessage) non-blocking message dispatch is not successful: relay-index=%d", relayIndex)
	} else {
		spanEmitter.FinishSpan("success")
	}
}

func (s *MessageSwitch) nonblockingRelayPeerBroadcast(
	spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpan("switch-nonblock-relay-peer-broadcast")
	defer spanEmitter.FinishSpan("success")
	for _, msgDispatcher := range s.messageDispatchers {
		if !msgDispatcher.relayInst.NonblockingEmitMessage(spanEmitter, m) {
			spanEmitter.EventWarningf("(MessageSwitch::nonblockingRelayPeerBroadcast) non-blocking message dispatch is not successful: relay-index=%d", msgDispatcher.relayIndex)
		}
	}
}

func (s *MessageSwitch) checkCrossBarServiceConnectChanged(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpan("switch-check-crossbar-service-connect-changed")
	if s.crossBar.getCurrentKnownServiceModifyTimestamp() == 0 {
		spanEmitter.FinishSpan("success: empty modify timestamp")
		return
	}
	spanEmitter.EventInfof("(MessageSwitch::checkCrossBarServiceConnectChanged) service reference modified.")
	if err := s.crossBar.save(s.stateStore); nil != err {
		spanEmitter.EventErrorf("(MessageSwitch::checkCrossBarServiceConnectChanged) saving known service reference failed: %v", err)
	}
	connects := s.crossBar.makeServiceConnectsSnapshot()
	for connIndex, connInst := range connects {
		if connInst == nil {
			spanEmitter.EventInfof("(MessageSwitch::checkCrossBarServiceConnectChanged) empty service connection: index=%d.", connIndex)
		}
		connInst.setMessageSender(spanEmitter, s)
	}
	if err := s.refreshLocalServiceRef(spanEmitter); nil != err {
		spanEmitter.EventErrorf("(MessageSwitch::checkCrossBarServiceConnectChanged) update local service reference failed: %v", err)
	}
}

// emitRelayHeartbeat send heartbeat to relaies and collect losted relaies.
// Invoked by maintenance routine.
func (s *MessageSwitch) emitRelayHeartbeat(spanEmitter *qabalwrap.TraceEmitter) (linkLostRelay []int) {
	spanEmitter = spanEmitter.StartSpan("switch-emit-relay-heartbeat")
	for _, dispatcher := range s.messageDispatchers {
		if dispatcher.shouldEmitHeartbeat() {
			dispatcher.emitHeartbeatPing(spanEmitter)
		}
		if !dispatcher.checkLinkTrafficStatus(spanEmitter) {
			linkLostRelay = append(linkLostRelay, dispatcher.relayIndex)
			spanEmitter.EventWarningf("losted relay: %d", dispatcher.relayIndex)
		}
	}
	spanEmitter.FinishSpan("success")
	return
}

func (s *MessageSwitch) emitAllocateServiceIdentsRequest(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpan("switch-emit-allocate-service-ident-req")
	if s.primarySwitch {
		spanEmitter.FinishSpan("success: (MessageSwitch::requestServiceSerialAssignment) skip emitAllocateServiceIdentsRequest on primary switch.")
		return
	}
	reqMsg, err := s.crossBar.makeAllocateServiceIdentsRequest()
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::requestServiceSerialAssignment) cannot make AllocateServiceIdentsRequest: %v", err)
		return
	}
	if reqMsg == nil {
		spanEmitter.FinishSpan("success: empty allocate request")
		return
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.MessageContentAllocateServiceIdentsRequest, reqMsg)
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::requestServiceSerialAssignment) cannot create enveloped message: %v", err)
		return
	}
	primaryLink := s.crossBar.getServiceConnectBySerial(qabalwrap.PrimaryMessageSwitchServiceIdent)
	if (primaryLink == nil) || (!primaryLink.linkAvailable()) {
		spanEmitter.EventInfof("(MessageSwitch::requestServiceSerialAssignment) cannot reach primary switch.")
		primaryLink = nil
	}
	if primaryLink != nil {
		if err = primaryLink.emitMessage(spanEmitter, m); nil != err {
			spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::requestServiceSerialAssignment) cannot emit enveloped message: %v", err)
		} else {
			spanEmitter.FinishSpan("success: emitted allocate request for %d services with primary link", len(reqMsg.ServiceIdents))
		}
	} else {
		for relayIndex, relayInst := range s.crossBar.relayProviders {
			emitSuccess := relayInst.NonblockingEmitMessage(spanEmitter, m)
			spanEmitter.EventInfof("(MessageSwitch::requestServiceSerialAssignment) emit with relay (index=%d): success=%v.", relayIndex, emitSuccess)
		}
		spanEmitter.FinishSpan("success: emitted allocate request for %d services with relies", len(reqMsg.ServiceIdents))
	}
}

func (s *MessageSwitch) emitRootCertificateRequest(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpan("switch-emit-root-cert-req")
	if s.tlsCertProvider.HaveRootCertificate() {
		spanEmitter.FinishSpan("success: (MessageSwitch::emitRootCertificateRequest) skip emitRootCertificateRequest as root certificate existed.")
		return
	}
	if primaryLink := s.crossBar.getServiceConnectBySerial(qabalwrap.PrimaryMessageSwitchServiceIdent); (primaryLink == nil) || (!primaryLink.linkAvailable()) {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::emitRootCertificateRequest) cannot reach primary switch.")
		return
	}
	reqMsg := &qbw1grpcgen.RootCertificateRequest{
		Timestamp: time.Now().Unix(),
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(
		s.localServiceRef.SerialIdent, qabalwrap.PrimaryMessageSwitchServiceIdent,
		qabalwrap.MessageContentRootCertificateRequest, reqMsg)
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::emitRootCertificateRequest) cannot create enveloped message: %v", err)
		return
	}
	if err = s.forwardClearEnvelopedMessage(spanEmitter, m); nil != err {
		spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::emitRootCertificateRequest) cannot emit enveloped message: %v", err)
	} else {
		spanEmitter.FinishSpan("success: (MessageSwitch::emitRootCertificateRequest) sent RootCertificateRequest.")
	}
}

func (s *MessageSwitch) emitHostCertificateRequests(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpan("switch-emit-host-cert-reqs")
	hostNames := s.tlsCertProvider.CollectSelfSignedHosts(spanEmitter)
	if len(hostNames) == 0 {
		spanEmitter.FinishSpan("success: empty host names")
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
			spanEmitter.FinishSpanErrorf("failed: (MessageSwitch::emitHostCertificateRequests) cannot create enveloped message: %v", err)
			return
		}
		if err = s.forwardClearEnvelopedMessage(spanEmitter, m); nil != err {
			spanEmitter.EventErrorf("(MessageSwitch::emitHostCertificateRequests) cannot emit enveloped message: %v", err)
		} else {
			spanEmitter.EventInfof("(MessageSwitch::emitHostCertificateRequests) sent host certificate request: [%s].", hostN)
		}
	}
	spanEmitter.FinishSpan("success")
}

func (s *MessageSwitch) maintenanceWorks(ctx context.Context, waitGroup *sync.WaitGroup) {
	spanEmitter := s.diagnosisEmitter.StartTrace("switch-maintenance-work: init")
	defer waitGroup.Done()
	hndKnownServiceIdentsNotify, err := newKnownServiceIdentsNotifyHandler(spanEmitter, s)
	if nil != err {
		log.Printf("WARN: (MessageSwitch::maintenanceWorks) cannot build known service idents: %v", err)
	}
	ticker := time.NewTicker(time.Minute * 2)
	defer ticker.Stop()
	s.emitAllocateServiceIdentsRequest(spanEmitter)
	lostedRelayIndexes := newRelayIndexSet()
	spanEmitter.FinishSpan("success")
	running := true
	for running {
		spanEmitter = s.diagnosisEmitter.StartTrace("switch-maintenance-work: iteration %v", time.Now())
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
			spanEmitter.EventInfof("(MessageSwitch::maintenanceWorks) run tick routine.")
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
			spanEmitter.EventInfof("(MessageSwitch::maintenanceWorks) get stop notice.")
		}
		spanEmitter.FinishSpan("success")
	}
	spanEmitter = s.diagnosisEmitter.StartTrace("switch-maintenance-work: (MessageSwitch::maintenanceWorks) leaving maintenance work loop.")
	s.checkCrossBarServiceConnectChanged(spanEmitter)
	spanEmitter.FinishSpan("success: (MessageSwitch::maintenanceWorks) maintenance work loop stopped.")
}

// Setup prepare provider for operation.
// Should only invoke at maintenance thread in setup stage.
func (s *MessageSwitch) Setup(
	diagnosisEmitter *qabalwrap.DiagnosisEmitter,
	certProvider qabalwrap.CertificateProvider) (err error) {
	return
}

func (s *MessageSwitch) postSetup(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpan("switch-post-setup")
	defer spanEmitter.FinishSpan("success")
	relayProviders := s.crossBar.relayProviders
	s.messageDispatchers = make([]*messageDispatcher, len(relayProviders))
	for relayIndex, relayInst := range relayProviders {
		msgDispatcher := newMessageDispatcher(relayIndex, relayInst, s)
		s.messageDispatchers[relayIndex] = msgDispatcher
		relayInst.SetMessageDispatcher(spanEmitter, msgDispatcher)
		spanEmitter.EventInfof("connect relay provider instance (index=%d) with message dispatcher",
			relayIndex)
	}
	connects := s.crossBar.makeServiceConnectsSnapshot()
	for connIndex, connInst := range connects {
		if connInst == nil {
			spanEmitter.EventInfof("(MessageSwitch::postSetup) empty service connection: index=%d.", connIndex)
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
	if err = serviceProvider.Setup(s.diagnosisEmitter, &s.tlsCertProvider); nil != err {
		return
	}
	s.localServices = append(s.localServices, serviceProvider)
	return
}

func (s *MessageSwitch) Start(ctx context.Context, waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter) (err error) {
	if spanEmitter == nil {
		spanEmitter = s.diagnosisEmitter.StartTrace("message-switch-start")
	} else {
		spanEmitter = spanEmitter.StartSpan("message-switch-start")
	}
	if s.primarySwitch {
		s.crossBar.assignServiceSerialIdents(spanEmitter)
	}
	s.crossBar.postSetup(spanEmitter)
	s.postSetup(spanEmitter)
	if err = s.tlsCertProvider.PostSetup(waitGroup, spanEmitter); nil != err {
		spanEmitter.EventErrorf("cannot perform post setup of TLS certificate provider: %v", err)
	}
	waitGroup.Add(1)
	go s.maintenanceWorks(ctx, waitGroup)
	for _, svr := range s.localServices {
		if err = svr.Start(ctx, waitGroup, spanEmitter); nil != err {
			s.Stop()
			spanEmitter.FinishSpan("failed: cannot start service: %v", err)
			return
		}
	}
	spanEmitter.FinishSpan("success")
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
	spanEmitter = spanEmitter.StartSpan("switch-receive-message")
	switch m.MessageContentType() {
	case qabalwrap.MessageContentAllocateServiceIdentsRequest:
		if err = queueAllocateServiceIdentsRequest(spanEmitter, s, m); nil != err {
			spanEmitter.EventErrorf("(MessageSwitch::ReceiveMessage) queue allocate service ident request failed: %v", err)
		}
	case qabalwrap.MessageContentRootCertificateRequest:
		queueRootCertificateRequest(spanEmitter, s, m)
	case qabalwrap.MessageContentRootCertificateAssignment:
		if err = queueRootCertificateAssignment(spanEmitter, s, m); nil != err {
			spanEmitter.EventErrorf("(MessageSwitch::ReceiveMessage) queue root cert assignment failed: %v", err)
		}
	case qabalwrap.MessageContentHostCertificateRequest:
		if err = queueHostCertificateRequest(spanEmitter, s, m); nil != err {
			spanEmitter.EventErrorf("(MessageSwitch::ReceiveMessage) queue host cert request failed: %v", err)
		}
	case qabalwrap.MessageContentHostCertificateAssignment:
		if err = queueHostCertificateAssignment(spanEmitter, s, m); nil != err {
			spanEmitter.EventErrorf("(MessageSwitch::ReceiveMessage) queue host cert assignment failed: %v", err)
		}
	default:
		spanEmitter.EventWarningf("(MessageSwitch::ReceiveMessage) unprocess message from %d to %d [content-type=%d].",
			m.SourceServiceIdent, m.DestinationServiceIdent, m.MessageContentType())
	}
	if nil != err {
		spanEmitter.FinishSpan("failed: %v", err)
	} else {
		spanEmitter.FinishSpan("success")
	}
	return
}
