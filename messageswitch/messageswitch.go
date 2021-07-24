package messageswitch

import (
	"context"
	"log"
	"sync"
	"time"

	md5digest "github.com/go-marshaltemabu/go-md5digest"
	"google.golang.org/protobuf/proto"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

const localServiceRefContentIdent = qabalwrap.ContentIdentLocalServiceRef

// MessageSwitch provide message switching services.
type MessageSwitch struct {
	qabalwrap.ServiceBase

	localServiceRef *ServiceReference
	primarySwitch   bool

	stateStore *qabalwrap.StateStore

	tlsCertProvider qw1tlscert.Provider
	crossBar        crossBar
	precomputedKeys precomputedKeyCache

	localServices      []qabalwrap.ServiceProvider
	messageDispatchers []*messageDispatcher

	notifyPeerKnownServiceIdents  chan *knownServiceIdentsNotify
	allocateServiceIdentsRequests chan *ServiceReference
}

// NewMessageSwitch create new instance of MessageSwitch.
func NewMessageSwitch(
	stateStore *qabalwrap.StateStore,
	textIdent, dnCountry, dnOrganization string,
	primarySwitch bool) (s *MessageSwitch, err error) {
	aux := &MessageSwitch{
		notifyPeerKnownServiceIdents:  make(chan *knownServiceIdentsNotify, 2),
		allocateServiceIdentsRequests: make(chan *ServiceReference, 2),
	}
	if err = aux.tlsCertProvider.Init(dnCountry, dnOrganization, stateStore, primarySwitch); nil != err {
		log.Printf("ERROR: (NewMessageSwitch) init TLS certificate provider failed: %v", err)
		return
	}
	if err = aux.crossBar.Init(stateStore, textIdent, aux, primarySwitch); nil != err {
		log.Printf("ERROR: (NewMessageSwitch) init crossbar failed: %v", err)
		return
	}
	if conn := aux.crossBar.findServiceConnectByTextIdent(textIdent); conn == nil {
		log.Printf("ERROR: (NewMessageSwitch) not reach message switch service: %s", textIdent)
		err = ErrNotHavingMessageSwitchServiceRecord
		return
	} else {
		aux.localServiceRef = &conn.ServiceReference
	}
	s = aux
	return
}

func (s *MessageSwitch) refreshLocalServiceRef() (err error) {
	if conn := s.crossBar.findServiceConnectByTextIdent(s.localServiceRef.TextIdent); conn == nil {
		log.Printf("ERROR: (MessageSwitch::refreshLocalServiceRef) not reach message switch service: %s", s.localServiceRef.TextIdent)
		err = ErrNotHavingMessageSwitchServiceRecord
		return
	} else if (s.localServiceRef.SerialIdent != conn.SerialIdent) || (s.localServiceRef.UniqueIdent != conn.UniqueIdent) {
		log.Printf("WARN: (MessageSwitch::refreshLocalServiceRef) modify local service reference: %d => %d, %s => %s.",
			s.localServiceRef.SerialIdent, conn.SerialIdent, s.localServiceRef.UniqueIdent.String(), conn.UniqueIdent.String())
		s.localServiceRef = &conn.ServiceReference
	}
	var onDiskLocalServiceRef ServiceReference
	ok, err := s.stateStore.Unmarshal(localServiceRefContentIdent, &onDiskLocalServiceRef)
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::refreshLocalServiceRef) cannot unpack local service reference from disk: %v", err)
		return
	}
	if ok && (onDiskLocalServiceRef.SerialIdent == s.localServiceRef.SerialIdent) && (onDiskLocalServiceRef.UniqueIdent == s.localServiceRef.UniqueIdent) && (onDiskLocalServiceRef.TextIdent == s.localServiceRef.TextIdent) {
		return
	}
	err = s.stateStore.Marshal(localServiceRefContentIdent, s.localServiceRef)
	log.Printf("INFO: updating local service reference: result-error=%v", err)
	return
}

// forwardClearEnvelopedMessage send message to target service.
// Invoke at operating stage by local services.
func (s *MessageSwitch) forwardClearEnvelopedMessage(msg *qabalwrap.EnvelopedMessage) (err error) {
	srcServiceConn, destServiceConn, err := s.crossBar.getTransmitionConnects(msg.SourceServiceIdent, msg.DestinationServiceIdent)
	if nil != err {
		return
	}
	if hopCount := destServiceConn.linkHopCount(); hopCount == 0 {
		err = destServiceConn.serviceProvider.ReceiveMessage(msg)
	} else if hopCount < maxLinkHopCount {
		precompSharedKey := s.precomputedKeys.getEncryptSharedKey(srcServiceConn, destServiceConn)
		if err = msg.Encrypt(precompSharedKey); nil != err {
			return
		}
		err = destServiceConn.emitMessage(msg)
	} else {
		err = ErrRelayLinksUnreachable(msg.DestinationServiceIdent)
	}
	return
}

// forwardEncryptedEnvelopedMessage send message to target service.
// Invoke at operating stage by relay providers.
func (s *MessageSwitch) forwardEncryptedEnvelopedMessage(msg *qabalwrap.EnvelopedMessage) (err error) {
	srcServiceConn, destServiceConn, err := s.crossBar.getTransmitionConnects(msg.SourceServiceIdent, msg.DestinationServiceIdent)
	if nil != err {
		return
	}
	if hopCount := destServiceConn.linkHopCount(); hopCount == 0 {
		precompSharedKey := s.precomputedKeys.getDecryptSharedKey(srcServiceConn, destServiceConn)
		if err = msg.Decrypt(precompSharedKey); nil != err {
			return
		}
		err = destServiceConn.serviceProvider.ReceiveMessage(msg)
	} else if hopCount < maxLinkHopCount {
		err = destServiceConn.emitMessage(msg)
	} else {
		err = ErrRelayLinksUnreachable(msg.DestinationServiceIdent)
	}
	return
}

func (s *MessageSwitch) buildKnownServiceIdentsMessage() (msg *qabalwrap.EnvelopedMessage, digest md5digest.MD5Digest, err error) {
	knownServiceIdents, err := s.crossBar.makeKnownServiceIdentsSnapshot()
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::buildKnownServiceIdentsMessage) cannot have known service idents: %v", err)
		return
	}
	buf, err := proto.Marshal(knownServiceIdents)
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::buildKnownServiceIdentsMessage) marshal known service idents failed: %v", err)
		return
	}
	digest.SumBytes(buf)
	msg = qabalwrap.NewClearEnvelopedMessage(
		qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent,
		qabalwrap.MessageContentKnownServiceIdents, buf)
	return
}

func (s *MessageSwitch) nonblockingRelayPeerMessage(relayIndex int, m *qabalwrap.EnvelopedMessage) {
	if (relayIndex < 0) || (relayIndex >= len(s.messageDispatchers)) {
		log.Printf("ERROR: (MessageSwitch::nonblockingRelayPeerMessage) invalid relay index: %d", relayIndex)
		return
	}
	if !s.messageDispatchers[relayIndex].relayInst.NonblockingEmitMessage(m) {
		log.Printf("WARN: (MessageSwitch::nonblockingRelayPeerMessage) non-blocking message dispatch is not successful: relay-index=%d", relayIndex)

	}
}

func (s *MessageSwitch) nonblockingRelayPeerBroadcast(m *qabalwrap.EnvelopedMessage) {
	for _, msgDispatcher := range s.messageDispatchers {
		if !msgDispatcher.relayInst.NonblockingEmitMessage(m) {
			log.Printf("WARN: (MessageSwitch::nonblockingRelayPeerBroadcast) non-blocking message dispatch is not successful: relay-index=%d", msgDispatcher.relayIndex)
		}
	}
}

func (s *MessageSwitch) checkCrossBarServiceConnectChanged() {
	if s.crossBar.getCurrentKnownServiceModifyTimestamp() == 0 {
		return
	}
	log.Print("INFO: (MessageSwitch::checkCrossBarServiceConnectChanged) service reference modified.")
	if err := s.crossBar.save(s.stateStore); nil != err {
		log.Printf("ERROR: (MessageSwitch::checkCrossBarServiceConnectChanged) saving known service reference failed: %v", err)
	}
	connects := s.crossBar.makeServiceConnectsSnapshot()
	for _, conn := range connects {
		conn.setMessageSender(s)
	}
	if err := s.refreshLocalServiceRef(); nil != err {
		log.Printf("ERROR: (MessageSwitch::checkCrossBarServiceConnectChanged) update local service reference failed: %v", err)
	}
}

func (s *MessageSwitch) emitRelayHeartbeat() (linkLostRelay []int) {
	for _, dispatcher := range s.messageDispatchers {
		if dispatcher.shouldEmitHeartbeat() {
			dispatcher.emitHeartbeatPing()
		}
		if !dispatcher.checkLinkHeartbeat() {
			linkLostRelay = append(linkLostRelay, dispatcher.relayIndex)
		}
	}
	return
}

func (s *MessageSwitch) emitAllocateServiceIdentsRequest() {
	if s.primarySwitch {
		return
	}
	primaryLink := s.crossBar.getServiceConnectBySerial(0)
	if (primaryLink == nil) || (!primaryLink.linkAvailable()) {
		log.Print("INFO: (MessageSwitch::requestServiceSerialAssignment) cannot reach primary switch.")
		return
	}
	reqMsg, err := s.crossBar.makeAllocateServiceIdentsRequest()
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::requestServiceSerialAssignment) cannot make AllocateServiceIdentsRequest: %v", err)
		return
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.MessageContentAllocateServiceIdentsRequest, reqMsg)
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::requestServiceSerialAssignment) cannot create enveloped message: %v", err)
		return
	}
	if err = primaryLink.emitMessage(m); nil != err {
		log.Printf("ERROR: (MessageSwitch::requestServiceSerialAssignment) cannot emit enveloped message: %v", err)
	}
}

func (s *MessageSwitch) maintenanceWorks(ctx context.Context, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	hndKnownServiceIdentsNotify, err := newKnownServiceIdentsNotifyHandler(s)
	if nil != err {
		log.Printf("WARN: (MessageSwitch::maintenanceWorks) cannot build known service idents: %v", err)
	}
	ticker := time.NewTicker(time.Minute * 2)
	defer ticker.Stop()
	running := true
	for running {
		s.checkCrossBarServiceConnectChanged()
		select {
		case notice := <-s.notifyPeerKnownServiceIdents:
			hndKnownServiceIdentsNotify.handle(notice)
		case allocateServiceRef := <-s.allocateServiceIdentsRequests:
			handleAllocateServiceIdentsRequest(s, allocateServiceRef)
			hndKnownServiceIdentsNotify.checkChanges()
		case <-ticker.C:
			lostedRelay := s.emitRelayHeartbeat()
			s.crossBar.relayLinksLosted(lostedRelay)
			s.emitAllocateServiceIdentsRequest()
		case <-ctx.Done():
			running = false
			log.Print("INFO: (MessageSwitch::maintenanceWorks) get stop notice.")
		}
	}
	log.Print("TRACE: (MessageSwitch::maintenanceWorks) leaving maintenance work loop.")
	s.checkCrossBarServiceConnectChanged()
	log.Print("TRACE: (MessageSwitch::maintenanceWorks) maintenance work loop stopped.")
}

func (s *MessageSwitch) Setup(certProvider qabalwrap.CertificateProvider) (err error) {
	return
}

func (s *MessageSwitch) postSetup() {
	relayProviders := s.crossBar.relayProviders
	s.messageDispatchers = make([]*messageDispatcher, len(relayProviders))
	for relayIndex, relayInst := range relayProviders {
		s.messageDispatchers[relayIndex] = newMessageDispatcher(relayIndex, relayInst, s)
	}
	connects := s.crossBar.makeServiceConnectsSnapshot()
	for _, conn := range connects {
		conn.setMessageSender(s)
	}
}

// AddServiceProvider associate given service provider into message switch instance.
// Must only invoke at setup stage.
func (s *MessageSwitch) AddServiceProvider(textIdent string, serviceProvider qabalwrap.ServiceProvider) (err error) {
	if err = s.crossBar.attachServiceProvider(textIdent, serviceProvider); nil != err {
		return
	}
	if err = serviceProvider.Setup(&s.tlsCertProvider); nil != err {
		return
	}
	s.localServices = append(s.localServices, serviceProvider)
	return
}

func (s *MessageSwitch) Start(ctx context.Context, waitGroup *sync.WaitGroup) (err error) {
	if s.primarySwitch {
		s.crossBar.assignServiceSerialIdents()
	}
	s.crossBar.postSetup()
	s.postSetup()
	if err = s.tlsCertProvider.PostSetup(waitGroup); nil != err {
		log.Printf("ERROR: cannot perform post setup of TLS certificate provider: %v", err)
	}
	waitGroup.Add(1)
	go s.maintenanceWorks(ctx, waitGroup)
	for _, svr := range s.localServices {
		if err = svr.Start(ctx, waitGroup); nil != err {
			s.Stop()
			return
		}
	}
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
func (s *MessageSwitch) ReceiveMessage(m *qabalwrap.EnvelopedMessage) (err error) {
	switch m.MessageContentType() {
	case qabalwrap.MessageContentAllocateServiceIdentsRequest:
		if err = queueAllocateServiceIdentsRequest(s, m); nil != err {
			log.Printf("ERROR: (MessageSwitch::ReceiveMessage) queue allocate service ident request failed: %v", err)
		}
	}
	return
}
