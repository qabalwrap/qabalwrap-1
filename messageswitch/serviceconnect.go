package messageswitch

import (
	"sort"
	"sync"

	"github.com/google/uuid"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type serviceConnect struct {
	ServiceReference

	serviceInstIdent qabalwrap.ServiceInstanceIdentifier

	// linkHopCount is overall hop count from this node to given service.
	// The value should modify in maintenance thread at setup stage, concurrent read in messaging threads.
	lckLinkHopCount               sync.Mutex
	linkHopCountValue             int
	linkhopCountSwitchSerialIdent int

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

func fillKnownServiceIdentsMessage(msg *qbw1grpcgen.KnownServiceIdents, refs []*serviceConnect, localSwitchSerialIdent int) (err error) {
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
		linkHopCountValue, linkHopSwitchSerialIdent := srvRef.linkHopStat()
		if linkHopCountValue == 0 {
			linkHopSwitchSerialIdent = localSwitchSerialIdent
		}
		srvIdent := qbw1grpcgen.ServiceIdent{
			UniqueIdent:              srvRef.UniqueIdent.String(),
			SerialIdent:              int32(srvRef.SerialIdent),
			TextIdent:                srvRef.TextIdent,
			PublicKey:                publicKeyBuf,
			LinkHopCount:             int32(linkHopCountValue),
			LinkHopSwitchSerialIdent: int32(linkHopSwitchSerialIdent),
		}
		serviceIdents = append(serviceIdents, &srvIdent)
		// log.Printf("TRACE: (fillKnownServiceIdentsMessage) %d/%s hop=%d:%d.", srvRef.SerialIdent, srvRef.TextIdent, linkHopCountValue, linkHopSwitchSerialIdent)
	}
	msg.MaxSerialIdent = int32(maxSerialIdent)
	if len(serviceIdents) > 0 {
		msg.ServiceIdents = serviceIdents
	}
	return
}

func newServiceConnect(containerServiceInstIdent qabalwrap.ServiceInstanceIdentifier, serviceRef *ServiceReference) (c *serviceConnect) {
	c = &serviceConnect{
		ServiceReference:  *serviceRef,
		serviceInstIdent:  containerServiceInstIdent + "-" + qabalwrap.ServiceInstanceIdentifier(serviceRef.TextIdent) + "-srvconn",
		linkHopCountValue: maxLinkHopCount,
	}
	return
}

func (c *serviceConnect) linkHopStat() (countValue, switchSerialIdent int) {
	c.lckLinkHopCount.Lock()
	defer c.lckLinkHopCount.Unlock()
	countValue = c.linkHopCountValue
	switchSerialIdent = c.linkhopCountSwitchSerialIdent
	return
}

func (c *serviceConnect) setLinkHopStat(countValue, switchSerialIdent int) {
	c.lckLinkHopCount.Lock()
	defer c.lckLinkHopCount.Unlock()
	c.linkHopCountValue = countValue
	c.linkhopCountSwitchSerialIdent = switchSerialIdent
}

func (c *serviceConnect) linkAvailable() bool {
	linkHopCountVal, _ := c.linkHopStat()
	return (linkHopCountVal < maxLinkHopCount)
}

func (c *serviceConnect) setServiceProvider(serviceProvider qabalwrap.ServiceProvider) {
	c.setLinkHopStat(0, qabalwrap.UnknownServiceIdent)
	c.serviceProvider = serviceProvider
}

// setRelayProviders connect given relayProviders with service.
// Should only invoke at setup stage or before service ident assignment.
func (c *serviceConnect) setRelayProviders(spanEmitter *qabalwrap.TraceEmitter, relayProviders []qabalwrap.RelayProvider) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(c.serviceInstIdent, "service-connect-set-relay-provider")
	if c == nil {
		spanEmitter.FinishSpan("success: empty service connect")
		return
	} else if c.serviceProvider != nil {
		spanEmitter.FinishSpan("success: service provider not empty")
		return
	} else if len(relayProviders) == len(c.relayStatsByIndex) {
		spanEmitter.FinishSpan("success: equal relay provider count")
		return
	}
	c.relayStatsByHop = newServiceRelays(relayProviders)
	c.relayStatsByIndex = make([]*serviceRelay, len(c.relayStatsByHop))
	copy(c.relayStatsByIndex, c.relayStatsByHop)
	spanEmitter.FinishSpan("success")
}

func (c *serviceConnect) setMessageSender(spanEmitter *qabalwrap.TraceEmitter, s *MessageSwitch) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(c.serviceInstIdent, "service-connect-set-message-sender")
	if c == nil {
		spanEmitter.FinishSpan("success: empty service connect")
		return
	} else if c.alreadySetMessageSender {
		spanEmitter.FinishSpan("success: already set message sender (serial-ident=%d)", c.SerialIdent)
		return
	} else if c.serviceProvider == nil {
		spanEmitter.FinishSpan("success: service provider is empty (serial-ident=%d)", c.SerialIdent)
		return
	} else if c.SerialIdent == qabalwrap.UnknownServiceIdent {
		spanEmitter.FinishSpan("success: unknown service serial identifier")
		return
	}
	sender := newMessageSender(c.SerialIdent, s)
	c.serviceProvider.SetMessageSender(sender)
	c.alreadySetMessageSender = true
	spanEmitter.FinishSpan("success: associate service provider (%d) with message sender.", c.SerialIdent)
}

func (c *serviceConnect) updateRelayHopCount(spanEmitter *qabalwrap.TraceEmitter, relayIndex, hopCount, relaySwitchSerialIdent int) {
	if c.serviceProvider != nil {
		return
	}
	if (relayIndex < 0) || (relayIndex >= len(c.relayStatsByIndex)) {
		spanEmitter.EventError("(serviceConnect::updateRelayHopCount) invalid relay index: %d (realy-count=%d)", relayIndex, len(c.relayStatsByIndex))
		return
	}
	c.lckRelayStats.Lock()
	defer c.lckRelayStats.Unlock()
	c.relayStatsByIndex[relayIndex].updateHopStat(hopCount, relaySwitchSerialIdent)
	sort.Sort(serviceRelayByHopCount(c.relayStatsByHop))
	if len(c.relayStatsByHop) == 0 {
		return
	}
	minHopCount := c.relayStatsByHop[0].hopCount
	srcSwitchSerialIdent := c.relayStatsByHop[0].hopSwitchSerialIdent
	if minHopCount < maxLinkHopCount {
		minHopCount++
	}
	c.setLinkHopStat(minHopCount, srcSwitchSerialIdent)
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

func (c *serviceConnect) emitMessage(spanEmitter *qabalwrap.TraceEmitter, envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan(c.serviceInstIdent, "service-connect-emit-message", "dst=%d", envelopedMessage.DestinationServiceIdent)
	relayProviders := c.relayProvidersInEmitOrder()
	if len(relayProviders) == 0 {
		err = ErrRelayLinksUnreachable(c.SerialIdent)
		spanEmitter.FinishSpan("failed: relay links unreachable")
		return
	}
	for _, relayProvider := range relayProviders {
		if err = relayProvider.BlockingEmitMessage(spanEmitter, envelopedMessage); nil != err {
			continue
		}
		spanEmitter.FinishSpan("success")
		return
	}
	spanEmitter.FinishSpanLogError("failed: (serviceConnect::emitMessage) emit message for [%s]: err=%v", c.TextIdent, err)
	return
}
