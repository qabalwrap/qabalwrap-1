package messageswitch

import (
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type knownServiceIdentsNotify struct {
	relayIndex         int
	knownServiceIdents *qbw1grpcgen.KnownServiceIdents
}
