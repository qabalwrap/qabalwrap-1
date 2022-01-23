package messageswitch

import (
	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

type knownServiceIdentsNotify struct {
	spanEmitter        *qabalwrap.TraceEmitter
	relayIndex         int
	knownServiceIdents *qbw1grpcgen.KnownServiceIdents
}

type relayLinkEstablishNotify struct {
	spanEmitter *qabalwrap.TraceEmitter
	relayIndex  int
}

type hostCertRequest struct {
	spanEmitter       *qabalwrap.TraceEmitter
	sourceSerialIdent int
	hostName          string
}

type hostCertAssignment struct {
	spanEmitter *qabalwrap.TraceEmitter
	hostName    string
	certKeyPair *qw1tlscert.CertificateKeyPair
}

type rootCertRequest struct {
	spanEmitter        *qabalwrap.TraceEmitter
	sourceServiceIdent int
}

type rootCertAssignment struct {
	spanEmitter *qabalwrap.TraceEmitter
	certKeyPair *qw1tlscert.CertificateKeyPair
}

type serviceReferenceRequest struct {
	SpanEmitter *qabalwrap.TraceEmitter
	ServiceRef  *ServiceReference
}
