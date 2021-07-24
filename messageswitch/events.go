package messageswitch

import (
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

type knownServiceIdentsNotify struct {
	relayIndex         int
	knownServiceIdents *qbw1grpcgen.KnownServiceIdents
}

type hostCertRequest struct {
	sourceSerialIdent int
	hostName          string
}

type hostCertAssignment struct {
	hostName    string
	certKeyPair *qw1tlscert.CertificateKeyPair
}
