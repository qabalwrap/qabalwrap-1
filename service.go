package qabalwrap

import (
	"crypto/rand"
	"crypto/tls"
	"log"
	"math"
	"sync"

	keybinary "github.com/go-marshaltemabu/go-keybinary"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

// MaxServiceIdentLength define max length of service identifier.
const MaxServiceIdentLength = 128

const (
	PrimaryMessageSwitchServiceIdent   int = 0
	AssignableServiceIdentMin              = 1
	AssignableServiceIdentMax              = (8192 - 1)
	AccessProviderPeerServiceIdent         = math.MaxInt16 - 2
	MessageSwitchBroadcastServiceIdent     = math.MaxInt16 - 1
	UnknownServiceIdent                    = -1
)

const (
	maxLinkHopCount        = int(math.MaxInt32)
	reasonableLinkHopCount = 7
)

type ServiceReference struct {
	UniqueIdent uuid.UUID             `json:"u"`
	SerialIdent int                   `json:"i"`
	TextIdent   string                `json:"t"`
	PublicKey   keybinary.ByteArray32 `json:"p"`
	PrivateKey  keybinary.ByteArray32 `json:"s"`

	linkHopCount   int
	relayHopCounts []int
	relayLinks     []RelayProvider

	serviceProvider ServiceProvider
}

func newServiceReference() (ref *ServiceReference, err error) {
	pubKey, priKey, err := box.GenerateKey(rand.Reader)
	if nil != err {
		return
	}
	ref = &ServiceReference{
		UniqueIdent: uuid.New(),
		SerialIdent: UnknownServiceIdent,
		PublicKey:   *keybinary.NewByteArray32(pubKey),
		PrivateKey:  *keybinary.NewByteArray32(priKey),
	}
	return
}

// IsNormalSerialIdent check if serial identifier value is located within assignable range.
func (ref *ServiceReference) IsNormalSerialIdent() bool {
	return (ref.SerialIdent >= AssignableServiceIdentMin) && (ref.SerialIdent <= AssignableServiceIdentMax)
}

// SetServiceProvider assign given serviceProvider to this reference.
func (ref *ServiceReference) SetServiceProvider(serviceProvider ServiceProvider) {
	ref.serviceProvider = serviceProvider
	ref.linkHopCount = 0
}

// ExpandRelayHopCountSize reallocate size of relay provider related structures.
func (ref *ServiceReference) ExpandRelayHopCountSize(size int) {
	if d := (size - len(ref.relayHopCounts)); d == 1 {
		ref.relayHopCounts = append(ref.relayHopCounts, maxLinkHopCount)
	} else if d > 1 {
		n := make([]int, d)
		for idx := 0; idx < d; idx++ {
			n[idx] = maxLinkHopCount
		}
		ref.relayHopCounts = append(ref.relayHopCounts, n...)
	}
}

// UpdateRelayHopCount set relay hop count for given relay provider and rebuild relay candidate order.
func (ref *ServiceReference) UpdateRelayHopCount(relayInsts []RelayProvider, relayIndex int, hopCount int) {
	if ref.relayHopCounts[relayIndex] == hopCount {
		return
	}
	ref.relayHopCounts[relayIndex] = hopCount
	if ref.serviceProvider != nil {
		return
	}
	type relaySortItem struct {
		inst RelayProvider
		cnt  int
	}
	var aux []*relaySortItem
	for idx, cnt := range ref.relayHopCounts {
		if cnt > reasonableLinkHopCount {
			continue
		}
		x := len(aux)
		r := &relaySortItem{
			inst: relayInsts[idx],
			cnt:  cnt,
		}
		aux = append(aux, r)
		if x == 0 {
			continue
		}
		for x > 0 {
			i := x - 1
			if aux[i].cnt <= cnt {
				break
			}
			aux[x] = aux[i]
			x = i
		}
		aux[x] = r
	}
	if l := len(aux); l == 0 {
		ref.linkHopCount = maxLinkHopCount
		ref.relayLinks = nil
	} else {
		ref.linkHopCount = aux[0].cnt + 1
		ref.relayLinks = make([]RelayProvider, l)
		for idx, a := range aux {
			ref.relayLinks[idx] = a.inst
		}
	}
}

// HasReceiver check if any receiver is available.
func (ref *ServiceReference) HasReceiver() bool {
	return (len(ref.relayLinks) > 0) || (ref.serviceProvider != nil)
}

func makeSerialIdentIndexableServiceReferenceSlice(localServiceRef *ServiceReference, inputRefs []*ServiceReference) (resultRefs []*ServiceReference, contentChanged bool) {
	maxSerialIdent := 0
	for _, r := range inputRefs {
		if (r == nil) || (!r.IsNormalSerialIdent()) {
			continue
		}
		if r.SerialIdent > maxSerialIdent {
			maxSerialIdent = r.SerialIdent
		}
	}
	if localServiceRef.IsNormalSerialIdent() && (localServiceRef.SerialIdent > maxSerialIdent) {
		maxSerialIdent = localServiceRef.SerialIdent
	}
	resultRefs = make([]*ServiceReference, maxSerialIdent+1)
	for _, r := range inputRefs {
		if r == nil {
			continue
		}
		if !r.IsNormalSerialIdent() {
			contentChanged = true
			continue
		}
		resultRefs[r.SerialIdent] = r
	}
	if existedLocalServiceRef := resultRefs[localServiceRef.SerialIdent]; (existedLocalServiceRef != nil) && (existedLocalServiceRef.UniqueIdent != localServiceRef.UniqueIdent) {
		log.Printf("WARN: conflict local service reference: serial-ident=%d; local-unique-ident=%s, index-unique-ident=%s",
			localServiceRef.SerialIdent, localServiceRef.UniqueIdent.String(), existedLocalServiceRef.UniqueIdent.String())
		contentChanged = true
	}
	resultRefs[localServiceRef.SerialIdent] = localServiceRef
	if msgSwitchRef := resultRefs[0]; msgSwitchRef != nil {
		if msgSwitchRef.IsNormalSerialIdent() {
			resultRefs[0] = resultRefs[msgSwitchRef.SerialIdent]
		} else {
			resultRefs[0] = nil
			contentChanged = true
		}
	}
	return
}

type ContentEdgeProvider interface {
	ServiceProvider

	// Stop close all pending transfers.
	Stop()
}

type ContentFetchProvider interface {
	ServiceProvider
}

type AccessProvider interface {
	ServiceProvider
}

type RelayProvider interface {
	// SetMessageDispatcher should update dispatcher for this instance if relay provider.
	// This method is invoked on register this instance with message switch.
	SetMessageDispatcher(dispatcher *MessageDispatcher)

	// EmitMessage send given message through this provider.
	EmitMessage(rawMessage *RawMessage) (err error)

	// Start relay operation.
	Start(waitGroup *sync.WaitGroup)
}

type CertificateProvider interface {
	// GetHostTLSCertificates fetch certificates for given host names.
	GetHostTLSCertificates(hostNames []string) (tlsCerts []tls.Certificate, err error)
}

// ServiceProvider define interface for services.
type ServiceProvider interface {
	// ReceiveMessage deliver message into this instance of service provider.
	// The message should decypted before pass into this method.
	ReceiveMessage(rawMessage *RawMessage) (err error)

	// SetMessageSender bind given sender with this instance of service provider.
	SetMessageSender(messageSender *MessageSender)

	// SwitchAvailable is invoked when message switch is available.
	//SwitchAvailable()

	// RegisterAvailable is invoked when service register is available.
	//RegisterAvailable()

	// RegisterUpdated is invoked when records in service register is modified.
	//RegisterUpdated()
}
