package messageswitch

import (
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

const serviceRefsContentIdent = qabalwrap.ContentIdentServiceRefs

type crossBar struct {
	lckConnects           sync.Mutex
	connectsBySerialIdent []*serviceConnect
	connectsByTextIdent   map[string]*serviceConnect
	connectsByUUID        map[uuid.UUID]*serviceConnect
	unassignConnects      []*serviceConnect
	connectsModifyAt      int64

	// relayProviders contain all relay provider.
	// The slice should create and access in maintenance thread at setup and operating stage.
	relayProviders []qabalwrap.RelayProvider
}

func (b *crossBar) Init(
	stateStore *qabalwrap.StateStore,
	textIdent string,
	messageSwitchServiceProvider qabalwrap.ServiceProvider,
	primaryCrossBar bool) (err error) {
	if _, err = b.load(stateStore); nil != err {
		log.Printf("ERROR: (crossBar::Init) load service references failed: %v", err)
		return
	}
	if err = b.attachServiceProvider(textIdent, messageSwitchServiceProvider); nil != err {
		log.Printf("ERROR: (crossBar::Init) attach message switch failed: %v", err)
		return
	}
	if primaryCrossBar && ((len(b.connectsBySerialIdent) < 1) || (b.connectsBySerialIdent[0] == nil)) {
		b.assignServiceSerialIdents()
		b.connectsBySerialIdent[0] = b.connectsByTextIdent[textIdent]
	}
	return
}

func (b *crossBar) emptyServiceConnects() {
	b.connectsBySerialIdent = nil
	b.connectsByTextIdent = make(map[string]*serviceConnect)
	b.connectsByUUID = make(map[uuid.UUID]*serviceConnect)
	b.unassignConnects = nil
	b.connectsModifyAt = 0
}

// load service references from storage.
// Must only invoke on setup stage.
func (b *crossBar) load(stateStore *qabalwrap.StateStore) (ok bool, err error) {
	var serviceRefs []*ServiceReference
	if ok, err = stateStore.Unmarshal(serviceRefsContentIdent, &serviceRefs); nil != err {
		log.Printf("ERROR: (crossBar::load) unmarshal service references failed: %v", err)
		return
	} else if !ok {
		b.emptyServiceConnects()
		return
	} else if len(serviceRefs) < 2 {
		log.Printf("WARN: (crossBar::load) unpacked service reference too less: %d.", len(serviceRefs))
		b.emptyServiceConnects()
		return
	}
	maxSerialIdent := findMaxServiceSerialIdent(serviceRefs)
	if maxSerialIdent < qabalwrap.AssignableServiceIdentMin {
		b.emptyServiceConnects()
		return
	}
	connectsBySerialIdent := make([]*serviceConnect, maxSerialIdent+1)
	connectsByTextIdent := make(map[string]*serviceConnect)
	connectsByUUID := make(map[uuid.UUID]*serviceConnect)
	for _, svrRef := range serviceRefs[1:] {
		if (svrRef == nil) || !svrRef.IsNormalSerialIdent() {
			continue
		}
		if l := connectsBySerialIdent[svrRef.SerialIdent]; l != nil {
			log.Printf("WARN: serial slot already existed: serial-ident=%d, text-ident=%s.", l.SerialIdent, l.TextIdent)
		}
		if l := connectsByTextIdent[svrRef.TextIdent]; l != nil {
			log.Printf("WARN: message slot already existed: serial-ident=%d, text-ident=%s.", l.SerialIdent, l.TextIdent)
		}
		conn := newServiceConnect(svrRef)
		connectsBySerialIdent[svrRef.SerialIdent] = conn
		connectsByTextIdent[svrRef.TextIdent] = conn
		connectsByUUID[svrRef.UniqueIdent] = conn
	}
	if srvZero := serviceRefs[0]; (srvZero != nil) && (srvZero.SerialIdent >= 1) && (srvZero.SerialIdent < len(connectsBySerialIdent)) {
		connectsBySerialIdent[0] = connectsBySerialIdent[srvZero.SerialIdent]
	}
	b.connectsBySerialIdent = connectsBySerialIdent
	b.connectsByTextIdent = connectsByTextIdent
	b.connectsByUUID = connectsByUUID
	b.connectsModifyAt = 0
	ok = true
	return
}

// collectServiceReferencesForSave create slice of ServiceReference and collect references from service connects.
func (b *crossBar) collectServiceReferencesForSave() (serviceRefs []*ServiceReference) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	serviceRefs = make([]*ServiceReference, len(b.connectsBySerialIdent))
	for connIdx, connInst := range b.connectsBySerialIdent {
		if connInst == nil {
			continue
		}
		serviceRefs[connIdx] = &connInst.ServiceReference
	}
	b.connectsModifyAt = 0
	return
}

func (b *crossBar) save(stateStore *qabalwrap.StateStore) (err error) {
	serviceRefs := b.collectServiceReferencesForSave()
	return stateStore.Marshal(serviceRefsContentIdent, serviceRefs)
}

// addRelayProviders fetch relay providers from given serviceProvider.
// Must only invoke on setup stage.
// Should only invoke by attachServiceProvider().
func (b *crossBar) addRelayProviders(serviceProvider qabalwrap.ServiceProvider) {
	relayProviders := serviceProvider.RelayProviders()
	if len(relayProviders) == 0 {
		return
	}
	b.relayProviders = append(b.relayProviders, relayProviders...)
}

// attachServiceProvider add given service provider to crossbar.
// Must only invoke on setup stage.
func (b *crossBar) attachServiceProvider(textIdent string, serviceProvider qabalwrap.ServiceProvider) (err error) {
	conn := b.connectsByTextIdent[textIdent]
	if conn == nil {
		var serviceRef *ServiceReference
		if serviceRef, err = generateServiceReference(textIdent); nil != err {
			return
		}
		conn = newServiceConnect(serviceRef)
		b.unassignConnects = append(b.unassignConnects, conn)
	}
	conn.setServiceProvider(serviceProvider)
	b.addRelayProviders(serviceProvider)
	return
}

func (b *crossBar) postSetup() {
	for _, conn := range b.connectsBySerialIdent {
		conn.setRelayProviders(b.relayProviders)
	}
}

// relayLinkLosted mark relay of given index as lost on all service connections.
func (b *crossBar) relayLinkLosted(relayIndex int) {
	if (relayIndex < 0) || (relayIndex >= len(b.relayProviders)) {
		log.Printf("WARN: (relayLinkLosted) invalid relay index: %d", relayIndex)
		return
	}
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if len(b.connectsBySerialIdent) < 1 {
		return
	}
	for _, conn := range b.connectsBySerialIdent[1:] {
		if conn == nil {
			continue
		}
		conn.updateRelayHopCount(relayIndex, maxLinkHopCount)
	}
}

// relayLinksLosted mark relays in given indexes as lost on all service connections.
func (b *crossBar) relayLinksLosted(relayIndexes []int) {
	if len(relayIndexes) == 0 {
		return
	}
	for _, relayIndex := range relayIndexes {
		b.relayLinkLosted(relayIndex)
	}
}

// expandServiceConnectsSlice reserve spaces to contain given maxServiceIdent serial value.
// Will be invoke at operating stage.
func (b *crossBar) expandServiceConnectsSlice(maxServiceIdent int) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if (maxServiceIdent < qabalwrap.AssignableServiceIdentMin) || (maxServiceIdent > qabalwrap.AssignableServiceIdentMax) {
		log.Printf("WARN: (expandServiceConnectsSlice) attempt to expand service connects slice with invalid max service ident: %d.", maxServiceIdent)
		return
	}
	if l := len(b.connectsBySerialIdent); maxServiceIdent >= l {
		emptySlots := make([]*serviceConnect, (maxServiceIdent - l + 1))
		b.connectsBySerialIdent = append(b.connectsBySerialIdent, emptySlots...)
	}
}

// getServiceConnectBySerial find service connect instance with given serial identifier.
func (b *crossBar) getServiceConnectBySerial(serviceSerialIdent int) (conn *serviceConnect) {
	if serviceSerialIdent < 0 {
		return
	}
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if l := len(b.connectsBySerialIdent); serviceSerialIdent >= l {
		return
	}
	return b.connectsBySerialIdent[serviceSerialIdent]
}

// getServiceConnectByTextIdent search for services with serial assigned.
func (b *crossBar) getServiceConnectByTextIdent(textIdent string) (conn *serviceConnect) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	return b.connectsByTextIdent[textIdent]
}

// findServiceConnectByTextIdent also search for unassigned services.
func (b *crossBar) findServiceConnectByTextIdent(textIdent string) (conn *serviceConnect) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if conn = b.connectsByTextIdent[textIdent]; conn != nil {
		return
	}
	for _, c := range b.unassignConnects {
		if c.TextIdent == textIdent {
			return c
		}
	}
	return
}

// findServiceConnectByUUID also search for unassigned services.
func (b *crossBar) findServiceConnectByUUID(uniqueIdent uuid.UUID) (conn *serviceConnect) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if conn = b.connectsByUUID[uniqueIdent]; conn != nil {
		return
	}
	conn, _ = findServiceConnectByUUID(b.unassignConnects, uniqueIdent)
	return
}

// getServiceConnectByServiceReference get or add given service reference to crossbar.
// Must only invoke on operating stage.
func (b *crossBar) getServiceConnectByServiceReference(serviceRef *ServiceReference) (conn *serviceConnect) {
	if serviceRef.SerialIdent == qabalwrap.UnknownServiceIdent {
		log.Printf("WARN: (attachServiceReference) attempt to attach service reference with unassigned service ident: %d (text=%s, unique=%s)", serviceRef.SerialIdent, serviceRef.TextIdent, serviceRef.UniqueIdent.String())
		return
	}
	if !serviceRef.IsNormalSerialIdent() {
		log.Printf("WARN: (attachServiceReference) attempt to attach service reference with invalid service ident: %d (text=%s, unique=%s)", serviceRef.SerialIdent, serviceRef.TextIdent, serviceRef.UniqueIdent.String())
		return
	}
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if l := len(b.connectsBySerialIdent); serviceRef.SerialIdent < l {
		if conn = b.connectsBySerialIdent[serviceRef.SerialIdent]; nil != conn {
			return
		}
	}
	if conn = b.connectsByTextIdent[serviceRef.TextIdent]; nil != conn {
		return
	}
	if conn = b.connectsByUUID[serviceRef.UniqueIdent]; nil != conn {
		return
	}
	if l := len(b.connectsBySerialIdent); serviceRef.SerialIdent >= l {
		emptySlots := make([]*serviceConnect, (serviceRef.SerialIdent - l + 1))
		b.connectsBySerialIdent = append(b.connectsBySerialIdent, emptySlots...)
	}
	conn, assignedIndex := findServiceConnectByUUID(b.unassignConnects, serviceRef.UniqueIdent)
	if conn != nil {
		b.unassignConnects = removeServiceConnectAtIndex(b.unassignConnects, assignedIndex)
		conn.SerialIdent = serviceRef.SerialIdent
	} else {
		conn = newServiceConnect(serviceRef)
	}
	conn.setRelayProviders(b.relayProviders)
	b.connectsBySerialIdent[conn.SerialIdent] = conn
	b.connectsByTextIdent[conn.TextIdent] = conn
	b.connectsByUUID[conn.UniqueIdent] = conn
	b.connectsModifyAt = time.Now().UnixNano()
	return
}

// assignServiceSerialIdents set serial to unassign service connects.
// May invoke on setup and operating stage.
func (b *crossBar) assignServiceSerialIdents() {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if len(b.connectsBySerialIdent) == 0 {
		b.connectsBySerialIdent = append(b.connectsBySerialIdent, nil)
	}
	for _, conn := range b.unassignConnects {
		serialIdent := len(b.connectsBySerialIdent)
		conn.SerialIdent = serialIdent
		conn.setRelayProviders(b.relayProviders)
		b.connectsBySerialIdent = append(b.connectsBySerialIdent, conn)
		b.connectsByTextIdent[conn.TextIdent] = conn
		b.connectsByUUID[conn.UniqueIdent] = conn
	}
	b.unassignConnects = nil
	b.connectsModifyAt = time.Now().UnixNano()
}

// addUnassignedServiceConnectByServiceReference get or add given service reference to crossbar.
// Must only invoke on operating stage.
func (b *crossBar) addUnassignedServiceConnectByServiceReference(serviceRef *ServiceReference) (conn *serviceConnect) {
	if (serviceRef.SerialIdent != qabalwrap.UnknownServiceIdent) || serviceRef.IsNormalSerialIdent() {
		log.Printf("WARN: (addUnassignedServiceConnectByServiceReference) attempt to allocate service reference with assigned service ident: %d (text=%s, unique=%s)", serviceRef.SerialIdent, serviceRef.TextIdent, serviceRef.UniqueIdent.String())
		b.lckConnects.Lock()
		defer b.lckConnects.Unlock()
		if l := len(b.connectsBySerialIdent); (serviceRef.SerialIdent > 0) && (serviceRef.SerialIdent < l) {
			conn = b.connectsBySerialIdent[serviceRef.SerialIdent]
		}
		return
	}
	if conn = b.findServiceConnectByTextIdent(serviceRef.TextIdent); nil != conn {
		return
	}
	if conn = b.findServiceConnectByUUID(serviceRef.UniqueIdent); nil != conn {
		return
	}
	conn = newServiceConnect(serviceRef)
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	b.unassignConnects = append(b.unassignConnects, conn)
	return
}

func (b *crossBar) getTransmitionConnects(srcServiceIdent, destServiceIdent int) (srcServiceConn, destServiceConn *serviceConnect, err error) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	l := len(b.connectsBySerialIdent)
	if (srcServiceIdent < 0) || (srcServiceIdent >= l) {
		err = ErrSourceServiceIdentOutOfRange(srcServiceIdent)
		return
	}
	if (destServiceIdent < 0) || (destServiceIdent >= l) {
		err = ErrDestinationServiceIdentOutOfRange(destServiceIdent)
		return
	}
	if srcServiceConn = b.connectsBySerialIdent[srcServiceIdent]; srcServiceConn == nil {
		err = ErrSourceServiceIdentNotFound(srcServiceIdent)
		return
	}
	if destServiceConn = b.connectsBySerialIdent[destServiceIdent]; destServiceConn == nil {
		err = ErrDestinationServiceIdentNotFound(destServiceIdent)
		return
	}
	return
}

func (b *crossBar) getCurrentKnownServiceModifyTimestamp() (t int64) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	t = b.connectsModifyAt
	return
}

func (b *crossBar) makeServiceConnectsSnapshot() (connects []*serviceConnect) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	connects = make([]*serviceConnect, len(b.connectsBySerialIdent))
	copy(connects, b.connectsBySerialIdent)
	return
}

func (b *crossBar) makeUnassignedServiceConnectsSnapshot() (connects []*serviceConnect) {
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	connects = make([]*serviceConnect, len(b.unassignConnects))
	copy(connects, b.unassignConnects)
	return
}

func (b *crossBar) makeKnownServiceIdentsSnapshot() (msg *qbw1grpcgen.KnownServiceIdents, err error) {
	msg = &qbw1grpcgen.KnownServiceIdents{
		PrimarySerialIdent: qabalwrap.UnknownServiceIdent,
	}
	b.lckConnects.Lock()
	defer b.lckConnects.Unlock()
	if len(b.connectsBySerialIdent) <= 0 {
		return
	}
	if err = fillKnownServiceIdentsMessage(msg, b.connectsBySerialIdent); nil != err {
		log.Printf("ERROR: (makeKnownServiceIdentsSnapshot) cannot fulfill known service identifiers message: %v", err)
		return
	}
	return
}

func (b *crossBar) makeAllocateServiceIdentsRequest() (msg *qbw1grpcgen.AllocateServiceIdentsRequest, err error) {
	unassignedConns := b.makeUnassignedServiceConnectsSnapshot()
	unassignedLen := len(unassignedConns)
	if unassignedLen == 0 {
		return
	}
	serviceIdents := make([]*qbw1grpcgen.ServiceIdent, 0, unassignedLen)
	for _, conn := range unassignedConns {
		if (conn == nil) || (conn.serviceProvider == nil) {
			continue
		}
		publicKeyBuf, err := conn.PublicKey.MarshalBinary()
		if nil != err {
			log.Printf("ERROR: (crossBar::makeAllocateServiceIdentsRequest) cannot marshal public key [text-ident: %s]: %v", conn.TextIdent, err)
			continue
		}
		srvIdent := qbw1grpcgen.ServiceIdent{
			UniqueIdent: conn.UniqueIdent.String(),
			SerialIdent: qabalwrap.UnknownServiceIdent,
			TextIdent:   conn.TextIdent,
			PublicKey:   publicKeyBuf,
		}
		serviceIdents = append(serviceIdents, &srvIdent)
	}
	if len(serviceIdents) == 0 {
		return
	}
	msg = &qbw1grpcgen.AllocateServiceIdentsRequest{
		ServiceIdents: serviceIdents,
	}
	return
}
