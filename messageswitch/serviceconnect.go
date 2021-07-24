package messageswitch

import (
	"log"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type serviceConnect struct {
	ServiceReference

	// linkHopCount is overall hop count from this node to given service.
	// The value should modify in maintenance thread at setup stage, concurrent read in messaging threads.
	linkHopCountVal int32

	// relayStatsByHop and relayStatsByIndex contain stats for relays.
	// Ths slices will be `nil` if referenced service a local service.
	// The slice should create in maintenance thread at setup stage, concurrent read in messaging threads.
	lckRelayStats     sync.Mutex
	relayStatsByHop   []*serviceRelay
	relayStatsByIndex []*serviceRelay

	// serviceProvider reference to local service instance.
	// The reference should assigned in maintenance thread at setup stage, concurrent read in messaging threads.
	serviceProvider qabalwrap.ServiceProvider

	alreadySetMessageSender bool
}

func findServiceConnectByUUID(conns []*serviceConnect, targetUUID uuid.UUID) (*serviceConnect, int) {
	for idx, c := range conns {
		if c.UniqueIdent == targetUUID {
			return c, idx
		}
	}
	return nil, -1
}

func removeServiceConnectAtIndex(conns []*serviceConnect, targetIndex int) []*serviceConnect {
	l := len(conns)
	if l == 1 {
		return nil
	} else if lastIndex := (l - 1); targetIndex < lastIndex {
		conns[targetIndex] = conns[lastIndex]
		conns[lastIndex] = nil
		return conns[:lastIndex]
	} else {
		return conns[:lastIndex]
	}
}

func fillKnownServiceIdentsMessage(msg *qbw1grpcgen.KnownServiceIdents, refs []*serviceConnect) (err error) {
	if len(refs) < 1 {
		return
	}
	if primaryRef := refs[0]; primaryRef != nil {
		msg.PrimarySerialIdent = int32(primaryRef.SerialIdent)
	}
	serviceIdents := make([]*qbw1grpcgen.ServiceIdent, 0, len(refs[1:]))
	maxSerialIdent := 0
	for _, srvRef := range refs[1:] {
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
		linkHopCount := int32(srvRef.linkHopCount())
		srvIdent := qbw1grpcgen.ServiceIdent{
			UniqueIdent:  srvRef.UniqueIdent.String(),
			SerialIdent:  int32(srvRef.SerialIdent),
			TextIdent:    srvRef.TextIdent,
			PublicKey:    publicKeyBuf,
			LinkHopCount: linkHopCount,
		}
		serviceIdents = append(serviceIdents, &srvIdent)
		log.Printf("TRACE: (fillKnownServiceIdentsMessage) %d/%s hop=%d.", srvRef.SerialIdent, srvRef.TextIdent, linkHopCount)
	}
	msg.MaxSerialIdent = int32(maxSerialIdent)
	if len(serviceIdents) > 0 {
		msg.ServiceIdents = serviceIdents
	}
	return
}

func newServiceConnect(serviceRef *ServiceReference) (c *serviceConnect) {
	c = &serviceConnect{
		ServiceReference: *serviceRef,
		linkHopCountVal:  int32(maxLinkHopCount),
	}
	return
}

func (c *serviceConnect) linkHopCount() int {
	v := atomic.LoadInt32(&c.linkHopCountVal)
	return int(v)
}

func (c *serviceConnect) linkAvailable() bool {
	return (c.linkHopCount() < maxLinkHopCount)
}

func (c *serviceConnect) setServiceProvider(serviceProvider qabalwrap.ServiceProvider) {
	atomic.StoreInt32(&c.linkHopCountVal, 0)
	c.serviceProvider = serviceProvider
}

// setRelayProviders connect given relayProviders with service.
// Should only invoke at setup stage or before service ident assignment.
func (c *serviceConnect) setRelayProviders(relayProviders []qabalwrap.RelayProvider) {
	if (c.serviceProvider != nil) || (len(relayProviders) == len(c.relayStatsByIndex)) {
		return
	}
	c.relayStatsByHop = newServiceRelays(relayProviders)
	c.relayStatsByIndex = make([]*serviceRelay, len(c.relayStatsByHop))
	copy(c.relayStatsByIndex, c.relayStatsByHop)
}

func (c *serviceConnect) setMessageSender(s *MessageSwitch) {
	if c.alreadySetMessageSender || (c.serviceProvider == nil) || (c.SerialIdent == qabalwrap.UnknownServiceIdent) {
		return
	}
	sender := newMessageSender(c.SerialIdent, s)
	c.serviceProvider.SetMessageSender(sender)
	c.alreadySetMessageSender = true
	log.Printf("INFO: associate service provider (%d) with message sender.", c.SerialIdent)
}

func (c *serviceConnect) updateRelayHopCount(relayIndex, hopCount int) {
	if c.serviceProvider != nil {
		return
	}
	if (relayIndex < 0) || (relayIndex >= len(c.relayStatsByIndex)) {
		log.Printf("ERROR: (serviceConnect::updateRelayHopCount) invalid relay index: %d (realy-count=%d)", relayIndex, len(c.relayStatsByIndex))
		return
	}
	c.lckRelayStats.Lock()
	defer c.lckRelayStats.Unlock()
	c.relayStatsByIndex[relayIndex].hopCount = hopCount
	sort.Sort(serviceRelayByHopCount(c.relayStatsByHop))
	if len(c.relayStatsByHop) == 0 {
		return
	}
	minHopCount := c.relayStatsByHop[0].hopCount
	if minHopCount < maxLinkHopCount {
		minHopCount++
	}
	atomic.StoreInt32(&c.linkHopCountVal, int32(minHopCount))
}

func (c *serviceConnect) relayProvidersInEmitOrder() (relayProviders []qabalwrap.RelayProvider) {
	relayProviders = make([]qabalwrap.RelayProvider, 0, len(c.relayStatsByIndex))
	c.lckRelayStats.Lock()
	defer c.lckRelayStats.Unlock()
	for _, relaySt := range c.relayStatsByHop {
		if relaySt.hopCount >= maxLinkHopCount {
			return
		}
		relayProviders = append(relayProviders, relaySt.providerInst)
	}
	return
}

func (c *serviceConnect) emitMessage(envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	relayProviders := c.relayProvidersInEmitOrder()
	if len(relayProviders) == 0 {
		err = ErrRelayLinksUnreachable(c.SerialIdent)
		return
	}
	for _, relayProvider := range relayProviders {
		if err = relayProvider.BlockingEmitMessage(envelopedMessage); nil != err {
			continue
		}
		return
	}
	log.Printf("ERROR: emit message for [%s]: err=%v", c.TextIdent, err)
	return
}
