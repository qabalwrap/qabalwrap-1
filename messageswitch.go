package qabalwrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	md5digest "github.com/go-marshaltemabu/go-md5digest"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"

	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

const (
	defaultTLSHostAddress = "default-85f45c9e.example.net"
)

const (
	heartbeatUpdateSeconds            = 10
	maxAcceptableHeartbeatIdleSeconds = 60
)

const (
	maxAcceptableHopCount            = 7
	maxQueuedCertificateRequestCount = 8
)

const messageSwitchPeriodWorkCycleTime = time.Second * 15 // time.Minute * 3

type MessageSender struct {
	serviceSerialIdent int
	messageSwitch      *MessageSwitch
}

func (s *MessageSender) Send(destServiceIdent int, messageContentType MessageContentType, messageContent proto.Message) {
	buf, err := proto.Marshal(messageContent)
	if nil != err {
		log.Printf("ERROR: (MessageSender::Send) cannot marshal message: %v", err)
		return
	}
	msg := NewPlainRawMessage(s.serviceSerialIdent, destServiceIdent, messageContentType, buf)
	s.messageSwitch.TransmitRawMessage(msg)
}

func (s *MessageSender) GetServiceByTextIdent(textIdent string) (serviceRef *ServiceReference) {
	s.messageSwitch.lckServiceRefs.RLock()
	defer s.messageSwitch.lckServiceRefs.RUnlock()
	serviceRef = s.messageSwitch.serviceRefsByTextIdent[textIdent]
	return
}

type MessageDispatcher struct {
	relayIndex    int
	messageSwitch *MessageSwitch

	lastDispatchHeartbeatTimestamp int64
}

func (d *MessageDispatcher) processKnownServiceIdents(m *RawMessage) {
	peerChanged, localChanged, assignedServRefs := d.messageSwitch.processKnownServiceIdentsMessage(d.relayIndex, m)
	log.Printf("INFO: (MessageDispatcher::processPeerMessage) processed known service identifier messages: %d, changed=<local: %v, peer: %v>", d.relayIndex, localChanged, peerChanged)
	d.messageSwitch.bindMessageSenders(assignedServRefs)
	if localChanged {
		d.messageSwitch.broadcastKnownServiceIdentsMessage()
	} else if peerChanged {
		if err := d.messageSwitch.emitKnownServiceIdentsMessage(d.relayIndex); nil != err {
			log.Printf("ERROR: (MessageDispatcher::processPeerMessage) send known service idents to relay (%d) failed: %v", d.relayIndex, err)
		}
	}
	if err := d.messageSwitch.emitAllocateServiceIdentsRequest(d.relayIndex); nil != err {
		log.Printf("ERROR: (MessageDispatcher::processPeerMessage) emit allocate service idents request to relay (%d) failed: %v", d.relayIndex, err)
	}
}

func (d *MessageDispatcher) processPeerMessage(m *RawMessage) {
	switch m.MessageContentType() {
	case MessageContentKnownServiceIdents:
		d.processKnownServiceIdents(m)
	case MessageContentAllocateServiceIdentsRequest:
		d.messageSwitch.processAllocateServiceIdentsRequest(m)
	}
}

func (d *MessageDispatcher) DispatchRawMessage(m *RawMessage) {
	if currentTimestamp := time.Now().Unix(); (currentTimestamp - d.lastDispatchHeartbeatTimestamp) > heartbeatUpdateSeconds {
		d.lastDispatchHeartbeatTimestamp = currentTimestamp
		atomic.StoreInt64(&d.messageSwitch.relayLastDispatchHeartbeatTimestamp[d.relayIndex], currentTimestamp)
	}
	if m.DestinationServiceIdent == AccessProviderPeerServiceIdent {
		d.processPeerMessage(m)
		return
	}
	// log.Printf("TRACE: (MessageDispatcher::DispatchRawMessage) dispatching message to switch (s=%d, d=%d, hop=%d)", m.SourceServiceIdent, m.DestinationServiceIdent, m.RemainHops)
	d.messageSwitch.DispatchRawMessage(m)
}

type MessageSwitch struct {
	stateStore      *StateStore
	localServiceRef *ServiceReference
	primarySwitch   bool

	lckServiceRefs           sync.RWMutex
	serviceRefsBySerialIdent []*ServiceReference
	serviceRefsByTextIdent   map[string]*ServiceReference
	unassignServiceRefs      []*ServiceReference

	lastPrimaryLinkCheckTimestamp int64

	lckKnownServiceIdents     sync.Mutex
	messageKnownServiceIdents *RawMessage
	digestKnownServiceIdents  md5digest.MD5Digest

	lckPrecomputedSharedKey sync.Mutex
	precomputedSharedKey    map[uint32]*[32]byte

	lckRelayProviders                   sync.RWMutex
	relayProviders                      []RelayProvider
	relayKnownServiceIdentsDigests      []md5digest.MD5Digest
	relayLastDispatchHeartbeatTimestamp []int64

	certificateManager *CertificateManager
	certRequestQueue   CertificateRequestQueue

	messageSender *MessageSender

	httpServerServices  []*HTTPServerService
	accessProviders     []AccessProvider
	contentEdgeProvider []ContentEdgeProvider
}

func NewMessageSwitch(
	stateStore *StateStore,
	textIdent, dnCountry, dnOrganization string,
	primarySwitch bool) (s *MessageSwitch, err error) {
	aux := MessageSwitch{
		stateStore:           stateStore,
		primarySwitch:        primarySwitch,
		precomputedSharedKey: make(map[uint32]*[32]byte),
	}
	if err = aux.setupLocalServiceRef(textIdent); nil != err {
		return
	}
	if err = aux.setupServiceRefs(); nil != err {
		return
	}
	if err = aux.setupCertificateManager(dnCountry, dnOrganization); nil != err {
		return
	}
	aux.certRequestQueue.Init(maxQueuedCertificateRequestCount)
	s = &aux
	return
}

func (s *MessageSwitch) saveLocalServiceRef() (err error) {
	return s.stateStore.Marshal(ContentIdentLocalServiceRef, s.localServiceRef)
}

func (s *MessageSwitch) saveServiceRefs() (err error) {
	return s.stateStore.Marshal(ContentIdentServiceRefs, s.serviceRefsBySerialIdent)
}

func (s *MessageSwitch) saveCertificateRecords() (err error) {
	return s.stateStore.Marshal(ContentIdentCertificateManager, s.certificateManager)
}

func (s *MessageSwitch) setupLocalServiceRef(textIdent string) (err error) {
	var ok bool
	var localServiceRefInst ServiceReference
	if ok, err = s.stateStore.Unmarshal(ContentIdentLocalServiceRef, &localServiceRefInst); nil != err {
		log.Printf("ERROR: (MessageSwitch::setupLocalServiceRef) unmarshal local service ident failed: %v", err)
		return
	}
	if ok {
		if localServiceRefInst.TextIdent != textIdent {
			err = fmt.Errorf("conflict text ident: %s vs. %s", s.localServiceRef.TextIdent, textIdent)
			return
		}
		if localServiceRefInst.SerialIdent == UnknownServiceIdent {
			err = fmt.Errorf("unknown local service identifier in state (%d/%s)", localServiceRefInst.SerialIdent, localServiceRefInst.TextIdent)
			return
		}
		s.localServiceRef = &localServiceRefInst
	} else {
		if s.localServiceRef, err = newServiceReference(); nil != err {
			log.Printf("ERROR: (MessageSwitch::setupLocalServiceRef) generate local service reference failed: %v", err)
			return
		}
		s.localServiceRef.TextIdent = textIdent
		if err = s.saveLocalServiceRef(); nil != err {
			log.Printf("ERROR: (MessageSwitch::setupLocalServiceRef) marshal generated local service ident failed: %v", err)
			return
		}
	}
	s.localServiceRef.SetServiceProvider(s)
	return
}

func (s *MessageSwitch) setupServiceRefs() (err error) {
	var ok bool
	var serviceRefs []*ServiceReference
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	if ok, err = s.stateStore.Unmarshal(ContentIdentServiceRefs, &serviceRefs); nil != err {
		log.Printf("ERROR: (MessageSwitch::setupServiceRefs) unmarshal service references failed: %v", err)
		return
	}
	saveAgain := false
	if ok && (len(serviceRefs) > 0) {
		serviceRefs, saveAgain = makeSerialIdentIndexableServiceReferenceSlice(s.localServiceRef, serviceRefs)
		if s.primarySwitch {
			serviceRefs[0] = s.localServiceRef
		}
	} else if s.primarySwitch {
		if s.localServiceRef.SerialIdent == UnknownServiceIdent {
			s.localServiceRef.SerialIdent = AssignableServiceIdentMin
			if err = s.saveLocalServiceRef(); nil != err {
				log.Printf("ERROR: (MessageSwitch::setupServiceRefs) marshal local service ident failed: %v", err)
				return
			}
		} else if !s.localServiceRef.IsNormalSerialIdent() {
			err = fmt.Errorf("local service serial ident out of range: %d", s.localServiceRef.SerialIdent)
			return
		}
		serviceRefs = make([]*ServiceReference, s.localServiceRef.SerialIdent+1)
		serviceRefs[s.localServiceRef.SerialIdent] = s.localServiceRef
		serviceRefs[0] = s.localServiceRef
		saveAgain = true
	} else {
		serviceRefs = nil
	}
	s.serviceRefsBySerialIdent = serviceRefs
	s.serviceRefsByTextIdent = make(map[string]*ServiceReference)
	for _, ref := range serviceRefs {
		if ref == nil {
			continue
		}
		if ref.serviceProvider != nil {
			ref.linkHopCount = 0
		} else {
			ref.linkHopCount = maxLinkHopCount
		}
		s.serviceRefsByTextIdent[ref.TextIdent] = ref
	}
	if s.primarySwitch {
		s.serviceRefsBySerialIdent[0].linkHopCount = 0
	}
	if saveAgain {
		if err = s.saveServiceRefs(); nil != err {
			log.Printf("ERROR: (MessageSwitch::setupServiceRefs) marshal generated service references failed: %v", err)
			return
		}
	}
	if _, err = s.rebuildKnownServiceIdentsMessage(); nil != err {
		log.Printf("ERROR: (MessageSwitch::setupServiceRefs) rebuild known service idents failed: %v", err)
		return
	}
	return
}

func (s *MessageSwitch) setupCertificateManager(dnCountry, dnOrganization string) (err error) {
	var ok bool
	var certManager CertificateManager
	if ok, err = s.stateStore.Unmarshal(ContentIdentCertificateManager, &certManager); nil != err {
		log.Printf("ERROR: (MessageSwitch::setupCertificateManager) unmarshal certificate manager failed: %v", err)
		return
	}
	if ok {
		s.certificateManager = &certManager
		return
	}
	s.certificateManager = NewCertificateManager(dnCountry, dnOrganization)
	if s.primarySwitch {
		if err = s.certificateManager.SetupRootCA(); nil != err {
			log.Printf("ERROR: (MessageSwitch::setupCertificateManager) cannot setup root CA: %v", err)
		}
		if err = s.saveCertificateRecords(); nil != err {
			log.Printf("ERROR: (MessageSwitch::setupCertificateManager) marshal certificate manager failed: %v", err)
			return
		}
	}
	return
}

// getTransmitPartiesServiceReferences fetch service reference of source and destination parties of given message.
// CAUTION: caller must acquire s.lckServiceRefs before invoke this method.
func (s *MessageSwitch) getTransmitPartiesServiceReferences(srcServiceIdent, destServiceIdent int) (srcServiceRef, destServiceRef *ServiceReference, ok bool) {
	serialIdentBound := len(s.serviceRefsBySerialIdent)
	if (srcServiceIdent < 0) || (srcServiceIdent >= serialIdentBound) {
		log.Printf("WARN: (MessageSwitch::getTransmitPartiesServiceReferences) source service identifier out of range: dest-serial-ident=%d, src-serial-ident=%d",
			destServiceIdent, srcServiceIdent)
		return
	}
	if (destServiceIdent < 0) || (destServiceIdent >= serialIdentBound) {
		log.Printf("WARN: (MessageSwitch::getTransmitPartiesServiceReferences) destination service identifier out of range: dest-serial-ident=%d, src-serial-ident=%d",
			destServiceIdent, srcServiceIdent)
		return
	}
	if srcServiceRef = s.serviceRefsBySerialIdent[srcServiceIdent]; srcServiceRef == nil {
		log.Printf("WARN: (MessageSwitch::getTransmitPartiesServiceReferences) source service reference is empty [%d].", srcServiceIdent)
		return
	}
	if destServiceRef = s.serviceRefsBySerialIdent[destServiceIdent]; destServiceRef == nil {
		log.Printf("WARN: (MessageSwitch::getTransmitPartiesServiceReferences) destination service reference is empty [%d].", destServiceIdent)
		return
	}
	ok = true
	return
}

// getPrecomputedEncryptKey for given message.
// CAUTION: lckServiceRefs will be acquire and release in this method.
func (s *MessageSwitch) getPrecomputedEncryptKey(srcServiceIdent, destServiceIdent int) (sharedKey *[32]byte, srcServiceRef, destServiceRef *ServiceReference) {
	s.lckServiceRefs.RLock()
	defer s.lckServiceRefs.RUnlock()
	srcServiceRef, destServiceRef, ok := s.getTransmitPartiesServiceReferences(srcServiceIdent, destServiceIdent)
	if !ok {
		return
	}
	cacheKey := ((uint32(destServiceIdent) << 16) & 0xFFFF0000) | (uint32(srcServiceIdent) & 0xFFFF)
	s.lckPrecomputedSharedKey.Lock()
	defer s.lckPrecomputedSharedKey.Unlock()
	if sharedKey = s.precomputedSharedKey[cacheKey]; nil != sharedKey {
		return
	}
	sharedKey = new([32]byte)
	box.Precompute(sharedKey, destServiceRef.PublicKey.Ref(), srcServiceRef.PrivateKey.Ref())
	s.precomputedSharedKey[cacheKey] = sharedKey
	return
}

// getPrecomputedDecryptKey for given message.
// CAUTION: lckServiceRefs will be acquire and release in this method.
func (s *MessageSwitch) getPrecomputedDecryptKey(m *RawMessage) (sharedKey *[32]byte, srcServiceRef, destServiceRef *ServiceReference) {
	s.lckServiceRefs.RLock()
	defer s.lckServiceRefs.RUnlock()
	srcServiceRef, destServiceRef, ok := s.getTransmitPartiesServiceReferences(m.SourceServiceIdent, m.DestinationServiceIdent)
	if !ok {
		return
	}
	if destServiceRef.linkHopCount != 0 {
		return
	}
	cacheKey := ((uint32(m.SourceServiceIdent) << 16) & 0xFFFF0000) | (uint32(m.DestinationServiceIdent) & 0xFFFF)
	s.lckPrecomputedSharedKey.Lock()
	defer s.lckPrecomputedSharedKey.Unlock()
	if sharedKey = s.precomputedSharedKey[cacheKey]; nil != sharedKey {
		return
	}
	sharedKey = new([32]byte)
	box.Precompute(sharedKey, srcServiceRef.PublicKey.Ref(), destServiceRef.PrivateKey.Ref())
	s.precomputedSharedKey[cacheKey] = sharedKey
	return
}

func (s *MessageSwitch) DispatchRawMessage(m *RawMessage) {
	sharedKey, _, destServiceRef := s.getPrecomputedDecryptKey(m)
	s.lckServiceRefs.RLock()
	defer s.lckServiceRefs.RUnlock()
	if sharedKey != nil {
		if (destServiceRef.linkHopCount == 0) && (destServiceRef.serviceProvider != nil) {
			if err := m.Decrypt(sharedKey); nil != err {
				log.Printf("WARN: (MessageSwitch::DispatchRawMessage) decryption failed: %v", err)
				return
			}
			destServiceRef.serviceProvider.ReceiveMessage(m)
			return
		}
		log.Printf("WARN: (MessageSwitch::DispatchRawMessage) cannot dispatch empty provider %d", destServiceRef.linkHopCount)
		return
	}
	log.Printf("TRACE: (MessageSwitch::DispatchRawMessage) cannot reach shared key: s=%d, d=%d, hop=%d.", m.SourceServiceIdent, m.DestinationServiceIdent, m.RemainHops)
	if m.RemainHops <= 0 {
		return
	}
	if m.RemainHops = m.RemainHops - 1; m.RemainHops > maxAcceptableHopCount {
		m.RemainHops = maxAcceptableHopCount
	}
	for relayIndex, relayInst := range destServiceRef.relayLinks {
		if err := relayInst.EmitMessage(m); nil == err {
			return
		} else {
			log.Printf("ERROR: (MessageSwitch::DispatchRawMessage) relay message failed (dest-serial=%d, relay-index=%d): %v",
				destServiceRef.SerialIdent, relayIndex, err)
		}
	}
}

func (s *MessageSwitch) TransmitRawMessage(m *RawMessage) {
	sharedKey, _, destServiceRef := s.getPrecomputedEncryptKey(m.SourceServiceIdent, m.DestinationServiceIdent)
	if (destServiceRef.linkHopCount == 0) && (destServiceRef.serviceProvider != nil) {
		// log.Printf("TRACE: (MessageSwitch::TransmitRawMessage) direct pass to service provider: s=%d, d=%d", m.SourceServiceIdent, m.DestinationServiceIdent)
		destServiceRef.serviceProvider.ReceiveMessage(m)
		return
	}
	if sharedKey == nil {
		log.Printf("ERROR: (MessageSwitch::TransmitRawMessage) cannot reach shared encrypt key: s=%d, d=%d", m.SourceServiceIdent, m.DestinationServiceIdent)
		return
	}
	if err := m.Encrypt(sharedKey); nil != err {
		log.Printf("ERROR: (MessageSwitch::TransmitRawMessage) cannot encrypt message: s=%d, d=%d; %v", m.SourceServiceIdent, m.DestinationServiceIdent, err)
		return
	}
	for relayIndex, relayInst := range destServiceRef.relayLinks {
		if err := relayInst.EmitMessage(m); nil == err {
			return
		} else {
			log.Printf("ERROR: (MessageSwitch::TransmitRawMessage) relay message failed (dest-serial=%d, relay-index=%d): %v",
				destServiceRef.SerialIdent, relayIndex, err)
		}
	}
	log.Printf("ERROR: (MessageSwitch::TransmitRawMessage) relay message failed (dest-serial=%d) out of links.",
		destServiceRef.SerialIdent)
}

func (s *MessageSwitch) loadHostCertificateFromPrimarySwitch(hostName string) (storageChanged bool) {
	sharedKey, srcServiceRef, destServiceRef := s.getPrecomputedEncryptKey(s.localServiceRef.SerialIdent, PrimaryMessageSwitchServiceIdent)
	if sharedKey == nil {
		log.Printf("ERROR: (MessageSwitch::loadHostCertificateFromPrimarySwitch) cannot locate encrypt key (src=%d, dest=%d).",
			s.localServiceRef.SerialIdent, PrimaryMessageSwitchServiceIdent)
		return
	}
	certReq := s.certRequestQueue.AllocateRequest()
	req := &qbw1grpcgen.HostCertificateRequest{
		RequestIdent: certReq.RequestIdent,
		HostDNSName:  hostName,
	}
	m, err := MarshalIntoEncryptedRawMessage(srcServiceRef.SerialIdent, destServiceRef.SerialIdent,
		sharedKey, MessageContentHostCertificateRequest, req)
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::loadHostCertificateFromPrimarySwitch) cannot create encrypted request: %v", err)
		return
	}
	emitted := false
	for idx, lnk := range destServiceRef.relayLinks {
		if err = lnk.EmitMessage(m); nil == err {
			log.Printf("INFO: (MessageSwitch::loadHostCertificateFromPrimarySwitch) emitted request (index=%d)", idx)
			emitted = true
			break
		}
		log.Printf("INFO: (MessageSwitch::loadHostCertificateFromPrimarySwitch) emit request failed (index=%d): %v", idx, err)
	}
	if !emitted {
		log.Printf("INFO: (MessageSwitch::loadHostCertificateFromPrimarySwitch) cannot emit request for [%s].", hostName)
		return
	}
	certKeyPair, err := certReq.Wait()
	if nil != err {
		log.Printf("INFO: (MessageSwitch::loadHostCertificateFromPrimarySwitch) waiting for certificate response failed): %v", err)
		return
	}
	s.certificateManager.SetHostKeyPair(hostName, certKeyPair)
	return true
}

func (s *MessageSwitch) getHostTLSCertificate(hostName string) (cert *tls.Certificate, storageChanged bool, err error) {
	if cert = s.certificateManager.GetHostTLSCertificate(hostName); cert != nil {
		return
	}
	if s.primarySwitch {
		if err = s.certificateManager.SetupHostKeyPair(hostName); nil != err {
			return
		}
		storageChanged = true
	} else {
		storageChanged = s.loadHostCertificateFromPrimarySwitch(hostName)
	}
	if cert = s.certificateManager.GetHostTLSCertificate(hostName); cert != nil {
		return
	}
	cert, err = s.certificateManager.MakeSelfSignedHostTLSCertificate(hostName)
	return
}

func (s *MessageSwitch) GetHostTLSCertificates(hostNames []string) (tlsCerts []tls.Certificate, err error) {
	tlsCerts = make([]tls.Certificate, len(hostNames)+1)
	cert, err := s.certificateManager.MakeSelfSignedHostTLSCertificate(defaultTLSHostAddress)
	if nil != err {
		return
	}
	tlsCerts[0] = *cert
	needSaveCertMgr := false
	for idx, hostName := range hostNames {
		var storageChanged bool
		if cert, storageChanged, err = s.getHostTLSCertificate(hostName); nil != err {
			return
		}
		needSaveCertMgr = needSaveCertMgr || storageChanged
		tlsCerts[idx+1] = *cert
	}
	if needSaveCertMgr {
		if err = s.saveCertificateRecords(); nil != err {
			log.Printf("ERROR: (MessageSwitch::GetHostTLSCertificates) marshal certificate manager failed: %v", err)
			return
		}
	}
	return
}

func (s *MessageSwitch) addUnassignedServiceIdents(unassignInsts []*ServiceReference) {
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	s.unassignServiceRefs = append(s.unassignServiceRefs, unassignInsts...)
}

// assignServiceSerialIdents set serial indentifiers to service references in unassign queue.
// CAUTION: This method should only invoke by primary switch.
func (s *MessageSwitch) assignServiceSerialIdents() (assignedServiceRef []*ServiceReference, knownServiceIdentsChanged bool, err error) {
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	if len(s.unassignServiceRefs) == 0 {
		return
	}
	freeSerialIdents := make([]int, 0, 4)
	for serialNum, srvRef := range s.serviceRefsBySerialIdent {
		if (srvRef == nil) && (serialNum > 0) {
			freeSerialIdents = append(freeSerialIdents, serialNum)
		}
	}
	existedUniqueIdents := make(map[uuid.UUID]struct{})
	for _, r := range s.serviceRefsBySerialIdent {
		if r == nil {
			continue
		}
		existedUniqueIdents[r.UniqueIdent] = struct{}{}
	}
	assignedServiceRef = make([]*ServiceReference, 0, len(s.unassignServiceRefs))
	for _, srvRef := range s.unassignServiceRefs {
		if r := s.serviceRefsByTextIdent[srvRef.TextIdent]; nil != r {
			log.Printf("WARN: (MessageSwitch::assignServiceSerialIdents) given text identifier existed: [%s]", srvRef.TextIdent)
			continue
		}
		if _, ok := existedUniqueIdents[srvRef.UniqueIdent]; ok {
			log.Printf("WARN: (MessageSwitch::assignServiceSerialIdents) given unique identifier existed: [%s]", srvRef.UniqueIdent)
			continue
		}
		existedUniqueIdents[srvRef.UniqueIdent] = struct{}{}
		var targetSerialIdent int
		if len(freeSerialIdents) > 0 {
			targetSerialIdent = freeSerialIdents[0]
			freeSerialIdents = freeSerialIdents[1:]
		} else {
			targetSerialIdent = len(s.serviceRefsBySerialIdent)
			s.serviceRefsBySerialIdent = append(s.serviceRefsBySerialIdent, nil)
		}
		srvRef.SerialIdent = targetSerialIdent
		s.serviceRefsBySerialIdent[targetSerialIdent] = srvRef
		s.serviceRefsByTextIdent[srvRef.TextIdent] = srvRef
		assignedServiceRef = append(assignedServiceRef, srvRef)
	}
	s.unassignServiceRefs = nil
	if err = s.saveServiceRefs(); nil != err {
		log.Printf("ERROR: (MessageSwitch::assignServiceSerialIdents) marshal updated service references failed: %v", err)
		return
	}
	if knownServiceIdentsChanged, err = s.rebuildKnownServiceIdentsMessage(); nil != err {
		log.Printf("ERROR: (MessageSwitch::assignServiceSerialIdents) rebuild known service idents failed: %v", err)
		return
	}
	return
}

func (s *MessageSwitch) prepareServiceReferenceViaTextIdent(textIdent string) (serviceRef *ServiceReference, err error) {
	if serviceRef = s.serviceRefsByTextIdent[textIdent]; serviceRef != nil {
		return
	}
	if serviceRef, err = newServiceReference(); nil != err {
		return
	}
	serviceRef.TextIdent = textIdent
	s.unassignServiceRefs = append(s.unassignServiceRefs, serviceRef)
	return
}

func (s *MessageSwitch) AddHTTPServerService(textIdent string, srv *HTTPServerService) (serviceRef *ServiceReference, err error) {
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	if serviceRef, err = s.prepareServiceReferenceViaTextIdent(textIdent); nil != err {
		return
	}
	serviceRef.SetServiceProvider(srv)
	s.httpServerServices = append(s.httpServerServices, srv)
	return
}

func (s *MessageSwitch) AddAccessProviderService(textIdent string, provider AccessProvider) (serviceRef *ServiceReference, err error) {
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	if serviceRef, err = s.prepareServiceReferenceViaTextIdent(textIdent); nil != err {
		return
	}
	serviceRef.SetServiceProvider(provider)
	s.accessProviders = append(s.accessProviders, provider)
	return
}

func (s *MessageSwitch) AddRelayProvider(relayProvider RelayProvider) {
	s.lckRelayProviders.Lock()
	defer s.lckRelayProviders.Unlock()
	relayIndex := len(s.relayProviders)
	dispatcher := &MessageDispatcher{
		relayIndex:    relayIndex,
		messageSwitch: s,
	}
	s.relayProviders = append(s.relayProviders, relayProvider)
	s.relayKnownServiceIdentsDigests = append(s.relayKnownServiceIdentsDigests, md5digest.MD5Digest{})
	s.relayLastDispatchHeartbeatTimestamp = append(s.relayLastDispatchHeartbeatTimestamp, 0)
	relayProvider.SetMessageDispatcher(dispatcher)
}

func (s *MessageSwitch) AddContentEdgeProvider(textIdent string, provider ContentEdgeProvider) (serviceRef *ServiceReference, err error) {
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	if serviceRef, err = s.prepareServiceReferenceViaTextIdent(textIdent); nil != err {
		return
	}
	s.contentEdgeProvider = append(s.contentEdgeProvider, provider)
	serviceRef.SetServiceProvider(provider)
	return
}

func (s *MessageSwitch) AddContentFetchProvider(textIdent string, provider ContentFetchProvider) (serviceRef *ServiceReference, err error) {
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	if serviceRef, err = s.prepareServiceReferenceViaTextIdent(textIdent); nil != err {
		return
	}
	serviceRef.SetServiceProvider(provider)
	return
}

// rebuildKnownServiceIdentsMessage update cached known service identifiers message.
// CAUTION: Read lock of s.lckServiceRefs must acquired before invoke this method.
func (s *MessageSwitch) rebuildKnownServiceIdentsMessage() (changed bool, err error) {
	msg := qbw1grpcgen.KnownServiceIdents{
		PrimarySerialIdent: UnknownServiceIdent,
	}
	s.lckKnownServiceIdents.Lock()
	defer s.lckKnownServiceIdents.Unlock()
	// s.lckServiceRefs.RLock()
	// defer s.lckServiceRefs.RUnlock()
	if len(s.serviceRefsBySerialIdent) > 0 {
		if primaryRef := s.serviceRefsBySerialIdent[0]; primaryRef != nil {
			msg.PrimarySerialIdent = int32(primaryRef.SerialIdent)
		}
		serviceIdents := make([]*qbw1grpcgen.ServiceIdent, 0, len(s.serviceRefsBySerialIdent[1:]))
		maxSerialIdent := 0
		for _, srvRef := range s.serviceRefsBySerialIdent[1:] {
			if srvRef == nil {
				continue
			}
			var publicKeyBuf []byte
			if publicKeyBuf, err = srvRef.PublicKey.MarshalBinary(); nil != err {
				return
			}
			if srvRef.SerialIdent > maxSerialIdent {
				maxSerialIdent = srvRef.SerialIdent
			}
			srvIdent := qbw1grpcgen.ServiceIdent{
				UniqueIdent:  srvRef.UniqueIdent.String(),
				SerialIdent:  int32(srvRef.SerialIdent),
				TextIdent:    srvRef.TextIdent,
				PublicKey:    publicKeyBuf,
				LinkHopCount: int32(srvRef.linkHopCount),
			}
			serviceIdents = append(serviceIdents, &srvIdent)
			log.Printf("TRACE: (rebuildKnownServiceIdentsMessage) %d/%s hop=%d.", srvRef.SerialIdent, srvRef.TextIdent, srvRef.linkHopCount)
		}
		msg.MaxSerialIdent = int32(maxSerialIdent)
		if len(serviceIdents) > 0 {
			msg.ServiceIdents = serviceIdents
		}
	}
	buf, err := proto.Marshal(&msg)
	var digest md5digest.MD5Digest
	digest.SumBytes(buf)
	if digest == s.digestKnownServiceIdents {
		return
	}
	s.messageKnownServiceIdents = NewPlainRawMessage(
		AccessProviderPeerServiceIdent, AccessProviderPeerServiceIdent,
		MessageContentKnownServiceIdents, buf)
	s.digestKnownServiceIdents = digest
	changed = true
	return
}

func (s *MessageSwitch) GetKnownServiceIdentsMessage() (msg *RawMessage) {
	s.lckKnownServiceIdents.Lock()
	defer s.lckKnownServiceIdents.Unlock()
	msg = s.messageKnownServiceIdents
	return
}

func (s *MessageSwitch) broadcastKnownServiceIdentsMessage() {
	msg := s.GetKnownServiceIdentsMessage()
	s.lckRelayProviders.RLock()
	defer s.lckRelayProviders.RUnlock()
	for relayIndex, relayProvider := range s.relayProviders {
		if err := relayProvider.EmitMessage(msg); nil != err {
			log.Printf("WARN: (MessageSwitch::broadcastKnownServiceIdentsMessage) broadcast known service idents failed (relay-index=%d): %v", relayIndex, err)
		}
	}
}

func (s *MessageSwitch) emitKnownServiceIdentsMessage(relayIndex int) (err error) {
	s.lckRelayProviders.RLock()
	defer s.lckRelayProviders.RUnlock()
	err = s.relayProviders[relayIndex].EmitMessage(s.GetKnownServiceIdentsMessage())
	return
}

// pickoutUnassignServiceRef remove and return service reference at given index.
// CAUTION: Caller must acquire the lock and ensure index is valid.
func (s *MessageSwitch) pickoutUnassignServiceRef(targetIndex int) (ref *ServiceReference) {
	ref = s.unassignServiceRefs[targetIndex]
	s.unassignServiceRefs[targetIndex] = nil
	if lastIndex := len(s.unassignServiceRefs) - 1; targetIndex == lastIndex {
		if lastIndex == 0 {
			s.unassignServiceRefs = nil
		} else {
			s.unassignServiceRefs = s.unassignServiceRefs[:lastIndex]
		}
	} else {
		s.unassignServiceRefs[targetIndex] = s.unassignServiceRefs[lastIndex]
		s.unassignServiceRefs[lastIndex] = nil
		s.unassignServiceRefs = s.unassignServiceRefs[:lastIndex]
	}
	return
}

func (s *MessageSwitch) processKnownServiceIdentsMessage(relayIndex int, m *RawMessage) (remoteKnownServiceIdentsChanged, localKnownServiceIdentsChanged bool, assignedServiceRefs []*ServiceReference) {
	var d0 md5digest.MD5Digest
	m.Digest(&d0)
	if s.relayKnownServiceIdentsDigests[relayIndex] == d0 { // remote state not change.
		return
	}
	remoteKnownServiceIdentsChanged = true
	s.relayKnownServiceIdentsDigests[relayIndex] = d0
	var knownSrvIdents qbw1grpcgen.KnownServiceIdents
	if err := m.Unmarshal(&knownSrvIdents); nil != err {
		log.Printf("ERROR: (MessageSwitch::processKnownServiceIdentsMessage) cannot unmarshal known service identifiers for relay-%d: %v", relayIndex, err)
		return
	}
	s.lckServiceRefs.Lock()
	defer s.lckServiceRefs.Unlock()
	if s.primarySwitch {
		for _, srvIdent := range knownSrvIdents.ServiceIdents {
			if (srvIdent.SerialIdent < 0) || (int(srvIdent.SerialIdent) >= len(s.serviceRefsBySerialIdent)) {
				log.Printf("ERROR: invalid serial from remote: %d", srvIdent.SerialIdent)
				continue
			}
			if r := s.serviceRefsBySerialIdent[srvIdent.SerialIdent]; r != nil {
				r.UpdateRelayHopCount(s.relayProviders, relayIndex, int(srvIdent.LinkHopCount))
				log.Printf("TRACE: (MessageSwitch::processKnownServiceIdentsMessage) update hop count ident=%d/%s => hop %d", srvIdent.SerialIdent, srvIdent.TextIdent, srvIdent.LinkHopCount)
			}
		}
		if err := s.emitKnownServiceIdentsMessage(relayIndex); nil != err {
			log.Printf("ERROR: (MessageSwitch::processKnownServiceIdentsMessage) cannot emit known service identifiers to relay-%d: %v", relayIndex, err)
		}
		return
	}
	if l := len(s.serviceRefsBySerialIdent); l <= int(knownSrvIdents.MaxSerialIdent) {
		sizeDiff := (int(knownSrvIdents.MaxSerialIdent) + 1) - l
		s.serviceRefsBySerialIdent = append(s.serviceRefsBySerialIdent, make([]*ServiceReference, sizeDiff)...)
	}
	for _, srvIdent := range knownSrvIdents.ServiceIdents {
		if (srvIdent.SerialIdent < -1) || (int(srvIdent.SerialIdent) >= len(s.serviceRefsBySerialIdent)) {
			log.Printf("ERROR: invalid serial from remote: %d", srvIdent.SerialIdent)
			continue
		}
		srvUniqueIdent, err := uuid.Parse(srvIdent.UniqueIdent)
		if nil != err {
			log.Printf("ERROR: (MessageSwitch::processKnownServiceIdentsMessage) cannot have givenunique identifier parse: [%s] %v",
				srvIdent.UniqueIdent, err)
			continue
		}
		targetUnassignedIndex := -1
		for idx, ref := range s.unassignServiceRefs {
			if ref == nil {
				continue
			}
			if ref.UniqueIdent == srvUniqueIdent {
				targetUnassignedIndex = idx
				break
			}
		}
		var ref *ServiceReference
		if targetUnassignedIndex != -1 {
			ref = s.pickoutUnassignServiceRef(targetUnassignedIndex)
			ref.SerialIdent = int(srvIdent.SerialIdent)
			assignedServiceRefs = append(assignedServiceRefs, ref)
		} else if r := s.serviceRefsBySerialIdent[int(srvIdent.SerialIdent)]; (r != nil) && (r.UniqueIdent == srvUniqueIdent) {
			log.Printf("TRACE: (MessageSwitch::processKnownServiceIdentsMessage) service reference existed %d [%s/%s] update hop=%d.", srvIdent.SerialIdent, srvIdent.UniqueIdent, srvIdent.TextIdent, srvIdent.LinkHopCount)
			r.UpdateRelayHopCount(s.relayProviders, relayIndex, int(srvIdent.LinkHopCount))
			continue
		} else {
			ref = &ServiceReference{
				UniqueIdent: srvUniqueIdent,
				SerialIdent: int(srvIdent.SerialIdent),
				TextIdent:   srvIdent.TextIdent,
			}
			if err := ref.PublicKey.UnmarshalBinary(srvIdent.PublicKey); nil != err {
				log.Printf("ERROR: (MessageSwitch::processKnownServiceIdentsMessage) cannot load public key [%s/%s]: %v", srvIdent.UniqueIdent, srvIdent.TextIdent, err)
				continue
			}
		}
		ref.ExpandRelayHopCountSize(len(s.relayProviders))
		ref.UpdateRelayHopCount(s.relayProviders, relayIndex, int(srvIdent.LinkHopCount))
		if r := s.serviceRefsBySerialIdent[ref.SerialIdent]; r != nil {
			log.Printf("WARN: (MessageSwitch::processKnownServiceIdentsMessage) overwrite service reference by serial identifier with unassigned one: %d [%s] => [%s]",
				ref.SerialIdent, r.TextIdent, ref.TextIdent)
		}
		if r := s.serviceRefsByTextIdent[ref.TextIdent]; r != nil {
			log.Printf("WARN: (MessageSwitch::processKnownServiceIdentsMessage) overwrite service reference by text identifier with unassigned one: %s/%s [%s] => [%s]",
				ref.TextIdent, r.TextIdent, r.UniqueIdent, ref.UniqueIdent)
		}
		s.serviceRefsBySerialIdent[ref.SerialIdent] = ref
		s.serviceRefsByTextIdent[ref.TextIdent] = ref
	}
	if (knownSrvIdents.PrimarySerialIdent > 0) && (int(knownSrvIdents.PrimarySerialIdent) < len(s.serviceRefsBySerialIdent)) {
		s.serviceRefsBySerialIdent[0] = s.serviceRefsBySerialIdent[knownSrvIdents.PrimarySerialIdent]
	}
	localKnownServiceIdentsChanged, err := s.rebuildKnownServiceIdentsMessage()
	if nil != err {
		log.Printf("WARN: (MessageSwitch::processKnownServiceIdentsMessage) having error when rebuild known service identifier message: %v", err)
	}
	if localKnownServiceIdentsChanged {
		if err = s.saveServiceRefs(); nil != err {
			log.Printf("ERROR: (MessageSwitch::processKnownServiceIdentsMessage) marshal updated service references failed: %v", err)
			return
		}
	}
	for _, r := range assignedServiceRefs {
		if r.UniqueIdent == s.localServiceRef.UniqueIdent {
			if err = s.saveLocalServiceRef(); nil != err {
				log.Printf("ERROR: (MessageSwitch::processKnownServiceIdentsMessage) marshal updated local service references failed: %v", err)
				return
			}
			break
		}
	}
	return
}

func (s *MessageSwitch) makeAllocateServiceIdentsRequest() (allocateReq *qbw1grpcgen.AllocateServiceIdentsRequest, err error) {
	s.lckServiceRefs.RLock()
	defer s.lckServiceRefs.RUnlock()
	if len(s.unassignServiceRefs) == 0 {
		return
	}
	serviceIdents := make([]*qbw1grpcgen.ServiceIdent, 0, len(s.unassignServiceRefs))
	for _, srvRef := range s.unassignServiceRefs {
		if srvRef == nil {
			continue
		}
		var publicKeyBuf []byte
		if publicKeyBuf, err = srvRef.PublicKey.MarshalBinary(); nil != err {
			return
		}
		srvIdent := qbw1grpcgen.ServiceIdent{
			UniqueIdent: srvRef.UniqueIdent.String(),
			SerialIdent: UnknownServiceIdent,
			TextIdent:   srvRef.TextIdent,
			PublicKey:   publicKeyBuf,
		}
		serviceIdents = append(serviceIdents, &srvIdent)
	}
	allocateReq = &qbw1grpcgen.AllocateServiceIdentsRequest{
		ServiceIdents: serviceIdents,
	}
	return
}

func (s *MessageSwitch) emitAllocateServiceIdentsRequest(relayIndex int) (err error) {
	allocateReq, err := s.makeAllocateServiceIdentsRequest()
	if (allocateReq == nil) || (nil != err) {
		return
	}
	buf, err := proto.Marshal(allocateReq)
	if nil != err {
		return
	}
	reqMsg := NewPlainRawMessage(AccessProviderPeerServiceIdent, AccessProviderPeerServiceIdent, MessageContentAllocateServiceIdentsRequest, buf)
	s.lckRelayProviders.RLock()
	defer s.lckRelayProviders.RUnlock()
	err = s.relayProviders[relayIndex].EmitMessage(reqMsg)
	return
}

func (s *MessageSwitch) forwardAllocateServiceIdentsRequest(m *RawMessage) {
	if s.localServiceRef.SerialIdent < AssignableServiceIdentMin {
		log.Printf("ERROR: (MessageSwitch::processAllocateServiceIdentsRequest) dropping allocate service idents request, invalid local serial: %d.", s.localServiceRef.SerialIdent)
		return
	}
	m.SourceServiceIdent = s.localServiceRef.SerialIdent
	m.DestinationServiceIdent = 0
	sharedEncKey, _, _ := s.getPrecomputedEncryptKey(m.SourceServiceIdent, m.DestinationServiceIdent)
	if err := m.Encrypt(sharedEncKey); nil != err {
		log.Printf("ERROR: (MessageSwitch::processAllocateServiceIdentsRequest) cannot encrypt allocate service idents requrest: %v", err)
		return
	}
	s.DispatchRawMessage(m)
}

func (s *MessageSwitch) processAllocateServiceIdentsRequest(m *RawMessage) {
	if !s.primarySwitch {
		s.forwardAllocateServiceIdentsRequest(m)
		return
	}
	var req qbw1grpcgen.AllocateServiceIdentsRequest
	if err := m.Unmarshal(&req); nil != err {
		log.Printf("ERROR: (MessageSwitch::processAllocateServiceIdentsRequest) cannot unpack request: %v", err)
		return
	}
	var unassignedSrvRefs []*ServiceReference
	for _, ref := range req.ServiceIdents {
		uniqIdent, err := uuid.Parse(ref.UniqueIdent)
		if nil != err {
			log.Printf("ERROR: (MessageSwitch::processAllocateServiceIdentsRequest) cannot parse unique identifier: %v", err)
			continue
		}
		if ref.TextIdent == "" {
			log.Printf("ERROR: (MessageSwitch::processAllocateServiceIdentsRequest) text identifier must not empty: [%s]", ref.TextIdent)
			continue
		}
		srvRef := &ServiceReference{
			UniqueIdent: uniqIdent,
			SerialIdent: UnknownServiceIdent,
			TextIdent:   ref.TextIdent,
		}
		if err := srvRef.PublicKey.UnmarshalBinary(ref.PublicKey); nil != err {
			log.Printf("ERROR: (MessageSwitch::processAllocateServiceIdentsRequest) cannot load public key [%s/%s]: %v", ref.UniqueIdent, ref.TextIdent, err)
			continue
		}
		unassignedSrvRefs = append(unassignedSrvRefs, srvRef)
	}
	if len(unassignedSrvRefs) == 0 {
		return
	}
	s.addUnassignedServiceIdents(unassignedSrvRefs)
	assignedSrvRefs, changed, err := s.assignServiceSerialIdents()
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::processAllocateServiceIdentsRequest) assign service identifier failed: %v", err)
	}
	s.bindMessageSenders(assignedSrvRefs)
	if changed {
		s.broadcastKnownServiceIdentsMessage()
	}
}

func (s *MessageSwitch) processHostCertificateRequest(m *RawMessage) {
	if !s.primarySwitch {
		log.Printf("ERROR: (MessageSwitch::processHostCertificateRequest) non-primary switch does not accept certificate request (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		return
	}
	var a qbw1grpcgen.HostCertificateRequest
	if err := m.Unmarshal(&a); nil != err {
		log.Printf("ERROR: (MessageSwitch::processHostCertificateRequest) unmarshal assignment failed: %v", err)
		return
	}
	hostName := a.HostDNSName
	log.Printf("INFO: (MessageSwitch::processHostCertificateRequest) request certificate for [%s]", hostName)
	certKeyPair := s.certificateManager.GetHostKeyPair(hostName)
	if certKeyPair == nil {
		if err := s.certificateManager.SetupHostKeyPair(hostName); nil != err {
			log.Printf("ERROR: (MessageSwitch::processHostCertificateRequest) setup host key pair failed [%s]: %v", hostName, err)
			return
		}
		if err := s.saveCertificateRecords(); nil != err {
			log.Printf("ERROR: (MessageSwitch::processHostCertificateRequest) marshal certificate manager failed: %v", err)
		}
		certKeyPair = s.certificateManager.GetHostKeyPair(hostName)
	}
	if certKeyPair == nil {
		log.Printf("ERROR: (MessageSwitch::processHostCertificateRequest) cannot setup host key pair [%s]", hostName)
		return
	}
	s.messageSender.Send(m.SourceServiceIdent, MessageContentHostCertificateAssignment, certKeyPair.QBw1HostCertificateAssignment(a.RequestIdent))
}

func (s *MessageSwitch) processHostCertificateAssignment(m *RawMessage) {
	if s.primarySwitch {
		log.Printf("ERROR: (MessageSwitch::processHostCertificateAssignment) primary switch does not accept certificate assignment (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		return
	}
	var a qbw1grpcgen.HostCertificateAssignment
	if err := m.Unmarshal(&a); nil != err {
		log.Printf("ERROR: (MessageSwitch::processHostCertificateAssignment) unmarshal assignment failed: %v", err)
		return
	}
	req := s.certRequestQueue.GetRequest(a.RequestIdent)
	if req == nil {
		log.Printf("ERROR: (MessageSwitch::processHostCertificateAssignment) host certificate request is gone: %d", a.RequestIdent)
		return
	}
	certKey, err := newCertificateKeyPairFromQBw1HostCertificateAssignment(&a)
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::processHostCertificateAssignment) create key pair from assignment failed: %v", err)
		return
	}
	req.Release(certKey)
}

func (s *MessageSwitch) processRootCertificateRequest(m *RawMessage) {
	if s.certificateManager.RootCertKeyPair == nil {
		log.Print("WARN: (MessageSwitch::processRootCertificateRequest) root certificate is empty")
		return
	}
	buf, err := proto.Marshal(&qbw1grpcgen.RootCertificateAssignment{
		Timestamp: time.Now().Unix(),
		CertDer:   s.certificateManager.RootCertKeyPair.CertDERBytes,
	})
	if nil != err {
		log.Printf("WARN: (MessageSwitch::processRootCertificateRequest) cannot marshal root certificate request: %v", err)
		return
	}
	msgResp := NewPlainRawMessage(s.localServiceRef.SerialIdent, m.SourceServiceIdent, MessageContentRootCertificateAssignment, buf)
	s.TransmitRawMessage(msgResp)
}

func (s *MessageSwitch) processRootCertificateAssignment(m *RawMessage) {
	if s.primarySwitch {
		log.Printf("ERROR: (MessageSwitch::processRootCertificateAssignment) primary switch does not accept root certificate assignment (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		return
	}
	var a qbw1grpcgen.RootCertificateAssignment
	if err := m.Unmarshal(&a); nil != err {
		log.Printf("ERROR: (MessageSwitch::processRootCertificateAssignment) unmarshal assignment failed: %v", err)
		return
	}
	rootCertKey, err := newCertificateKeyPair(a.CertDer, nil)
	if nil != err {
		log.Printf("ERROR: (MessageSwitch::processRootCertificateAssignment) unmarshal root certificate failed: %v", err)
		return
	}
	if changed, err := s.certificateManager.UpdateRootCertificate(rootCertKey); nil != err {
		log.Printf("ERROR: (MessageSwitch::processRootCertificateAssignment) unmarshal update root certificate failed: %v", err)
		return
	} else if changed {
		if err = s.saveCertificateRecords(); nil != err {
			log.Printf("ERROR: (MessageSwitch::processRootCertificateAssignment) marshal certificate manager failed: %v", err)
			return
		}
	}
}

func (s *MessageSwitch) bindMessageSenders(srvRefs []*ServiceReference) {
	if len(srvRefs) == 0 {
		return
	}
	s.lckServiceRefs.RLock()
	defer s.lckServiceRefs.RUnlock()
	for _, ref := range srvRefs {
		r := s.serviceRefsBySerialIdent[ref.SerialIdent]
		if (r == nil) || (r.serviceProvider == nil) {
			continue
		}
		r.serviceProvider.SetMessageSender(&MessageSender{
			serviceSerialIdent: ref.SerialIdent,
			messageSwitch:      s,
		})
		log.Printf("INFO: (MessageSwitch::bindMessageSenders) bind message sender to service %d/%s.", r.SerialIdent, r.TextIdent)
	}
}

// ReceiveMessage implement ServiceProvider interface.
func (s *MessageSwitch) ReceiveMessage(rawMessage *RawMessage) (err error) {
	switch rawMessage.MessageContentType() {
	case MessageContentAllocateServiceIdentsRequest:
		s.processAllocateServiceIdentsRequest(rawMessage)
	case MessageContentHostCertificateRequest:
		s.processHostCertificateRequest(rawMessage)
	case MessageContentHostCertificateAssignment:
		s.processHostCertificateAssignment(rawMessage)
	case MessageContentRootCertificateRequest:
		s.processRootCertificateRequest(rawMessage)
	case MessageContentRootCertificateAssignment:
		s.processRootCertificateAssignment(rawMessage)
	default:
		log.Printf("WARN: (MessageSwitch::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	}
	return
}

// SetMessageSender implement ServiceProvider interface.
func (s *MessageSwitch) SetMessageSender(messageSender *MessageSender) {
	s.messageSender = messageSender
}

func (s *MessageSwitch) doCertificateRootChecks() {
	if s.certificateManager.HaveRootCertificate() {
		return
	}
	s.messageSender.Send(PrimaryMessageSwitchServiceIdent, MessageContentRootCertificateRequest, &qbw1grpcgen.RootCertificateRequest{
		Timestamp: time.Now().Unix(),
	})
}

func (s *MessageSwitch) doCertificateRequestQueueChecks() {
	s.certRequestQueue.DropExpiredRequests()
}

func (s *MessageSwitch) doPrimaryLinkCheck() (linkUp bool) {
	if s.primarySwitch {
		return
	}
	prevLinkTimestamp := s.lastPrimaryLinkCheckTimestamp
	s.lckServiceRefs.RLock()
	defer s.lckServiceRefs.RUnlock()
	var currentLinkTimestamp int64
	if (len(s.serviceRefsBySerialIdent) > 0) && (len(s.serviceRefsBySerialIdent[0].relayLinks) > 0) {
		currentLinkTimestamp = time.Now().Unix()
	}
	s.lastPrimaryLinkCheckTimestamp = currentLinkTimestamp
	return (prevLinkTimestamp == 0) && (currentLinkTimestamp != 0)
}

func (s *MessageSwitch) onPrimaryLinkEstablished(waitGroup *sync.WaitGroup) {
	for idx, httpSrv := range s.httpServerServices {
		log.Printf("INFO: (MessageSwitch::onPrimaryLinkEstablished) stopping HTTP server service (index=%d)", idx)
		httpSrv.Stop()
		log.Printf("INFO: (MessageSwitch::onPrimaryLinkEstablished) stopped HTTP server service (index=%d)", idx)
		if err := httpSrv.Start(waitGroup, s); nil != err {
			log.Printf("WARN: (MessageSwitch::onPrimaryLinkEstablished) start http server failed: %v", err)
		} else {
			log.Printf("INFO: (MessageSwitch::onPrimaryLinkEstablished) started HTTP server service (index=%d)", idx)
		}
	}
}

func (s *MessageSwitch) runPeriodicalWorks(waitGroup *sync.WaitGroup, ctx context.Context) {
	defer waitGroup.Done()
	ticker := time.NewTicker(messageSwitchPeriodWorkCycleTime)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.doCertificateRequestQueueChecks()
			s.doCertificateRootChecks()
			if s.doPrimaryLinkCheck() {
				s.onPrimaryLinkEstablished(waitGroup)
			}
		}
	}
}

func (s *MessageSwitch) Start(waitGroup *sync.WaitGroup, ctx context.Context) (err error) {
	if s.primarySwitch {
		if _, _, err = s.assignServiceSerialIdents(); nil != err {
			log.Printf("WARN: (MessageSwitch::Start) assign service identifiers failed: %v", err)
			return
		}
	}
	if s.localServiceRef.SerialIdent == UnknownServiceIdent {
		s.unassignServiceRefs = append(s.unassignServiceRefs, s.localServiceRef)
	}
	if len(s.serviceRefsBySerialIdent) >= 2 {
		s.bindMessageSenders(s.serviceRefsBySerialIdent[1:])
	}
	if _, err = s.rebuildKnownServiceIdentsMessage(); nil != err {
		log.Printf("ERROR: (MessageSwitch::Start) refresh known service identifiers filaed: %v", err)
		return
	}
	for srvIndex, srvRef := range s.serviceRefsBySerialIdent {
		if srvRef == nil {
			log.Printf("WARN: empty service reference slot (index=%d).", srvIndex)
			continue
		}
		srvRef.ExpandRelayHopCountSize(len(s.relayProviders))
	}
	for _, httpSrv := range s.httpServerServices {
		if err = httpSrv.Start(waitGroup, s); nil != err {
			log.Printf("WARN: (MessageSwitch::Start) start http server failed: %v", err)
			return
		}
	}
	for _, relayInst := range s.relayProviders {
		relayInst.Start(waitGroup)
	}
	if !s.primarySwitch {
		for _, relayInst := range s.relayProviders {
			relayInst.EmitMessage(s.GetKnownServiceIdentsMessage())
		}
	}
	waitGroup.Add(1)
	go s.runPeriodicalWorks(waitGroup, ctx)
	return
}

func (s *MessageSwitch) Stop() {
	for _, provider := range s.contentEdgeProvider {
		provider.Stop()
	}
	for _, httpSrv := range s.httpServerServices {
		httpSrv.Stop()
	}
	s.certRequestQueue.Stop()
}
