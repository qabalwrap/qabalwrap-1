package messageswitch

import (
	"math"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

const (
	maxLinkHopCount        = int(math.MaxInt32)
	reasonableLinkHopCount = 7
)

// serviceRelay keep relay status for service instance.
// The content of this struct should only modify from maintenance thread.
type serviceRelay struct {
	hopCount     int
	providerInst qabalwrap.RelayProvider
}

type serviceRelayByHopCount []*serviceRelay

func (a serviceRelayByHopCount) Len() int {
	return len(a)
}

func (a serviceRelayByHopCount) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a serviceRelayByHopCount) Less(i, j int) bool {
	return a[i].hopCount < a[j].hopCount
}

func newServiceRelays(relayProviders []qabalwrap.RelayProvider) (serviceRelays []*serviceRelay) {
	serviceRelays = make([]*serviceRelay, len(relayProviders))
	for relayIndex, providerInst := range relayProviders {
		serviceRelays[relayIndex] = &serviceRelay{
			hopCount:     maxLinkHopCount,
			providerInst: providerInst,
		}
	}
	return
}
