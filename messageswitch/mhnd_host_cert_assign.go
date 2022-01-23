package messageswitch

import (
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

func queueHostCertificateAssignment(spanEmitter *qabalwrap.TraceEmitter, s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan("queue-host-cert-assign")
	if s.primarySwitch {
		spanEmitter.FinishSpanErrorf("failed: (queueHostCertificateAssignment) primary switch does not accept host certificate assignment (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		err = ErrNotSupportedOperation
		return
	}
	var a qbw1grpcgen.HostCertificateAssignment
	if err = m.Unmarshal(&a); nil != err {
		spanEmitter.FinishSpanErrorf("failed: (queueHostCertificateAssignment) unmarshal assignment failed: %v", err)
		return
	}
	hostCertKey, err := qw1tlscert.NewCertificateKeyPairFromQBw1HostCertificateAssignment(&a)
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (queueHostCertificateAssignment) unmarshal root certificate failed: %v", err)
		return
	}
	r := &hostCertAssignment{
		spanEmitter: spanEmitter,
		hostName:    a.HostDNSName,
		certKeyPair: hostCertKey,
	}
	s.hostCertificateAssignments <- r
	return
}

func handleHostCertificateAssignment(waitgroup *sync.WaitGroup, s *MessageSwitch, r *hostCertAssignment) (err error) {
	spanEmitter := r.spanEmitter.StartSpan("handle-host-cert-assign: (handleHostCertificateAssignment) [%s]", r.hostName)
	if err = s.tlsCertProvider.UpdateHostCertificate(waitgroup, spanEmitter, r.hostName, r.certKeyPair); nil != err {
		spanEmitter.FinishSpanErrorf("failed: (handleHostCertificateAssignment) update host cert failed [%s]: %v", r.hostName, err)
	} else {
		spanEmitter.FinishSpan("success")
	}
	return
}
