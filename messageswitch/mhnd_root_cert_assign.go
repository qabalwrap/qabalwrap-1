package messageswitch

import (
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

func queueRootCertificateAssignment(spanEmitter *qabalwrap.TraceEmitter, s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan("queue-root-cert-assign")
	if s.primarySwitch {
		spanEmitter.FinishSpanErrorf("failed: (queueRootCertificateAssignment) primary switch does not accept root certificate assignment (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		err = ErrNotSupportedOperation
		return
	}
	var a qbw1grpcgen.RootCertificateAssignment
	if err = m.Unmarshal(&a); nil != err {
		spanEmitter.FinishSpanErrorf("failed: (queueRootCertificateAssignment) unmarshal assignment failed: %v", err)
		return
	}
	rootCertKey, err := qw1tlscert.NewCertificateKeyPairFromQBw1RootCertificateAssignment(&a)
	if nil != err {
		spanEmitter.FinishSpanErrorf("failed: (queueRootCertificateAssignment) unmarshal root certificate failed: %v", err)
		return
	}
	s.rootCertificateAssignment <- &rootCertAssignment{
		spanEmitter: spanEmitter,
		certKeyPair: rootCertKey,
	}
	spanEmitter.FinishSpan("success")
	return
}

func handleRootCertificateAssignment(waitgroup *sync.WaitGroup, s *MessageSwitch, rootCertAssign *rootCertAssignment) (err error) {
	spanEmitter := rootCertAssign.spanEmitter.StartSpan("handle-root-cert-assign: (handleRootCertificateAssignment) have root cert assignment.")
	if err = s.tlsCertProvider.UpdateRootCertificate(waitgroup, spanEmitter, rootCertAssign.certKeyPair); nil != err {
		spanEmitter.FinishSpanErrorf("failed: (handleRootCertificateAssignment) update root cert failed: %v", err)
	} else {
		spanEmitter.FinishSpan("success")
	}
	return
}
