package messageswitch

import (
	"time"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

func queueRootCertificateRequest(
	spanEmitter *qabalwrap.TraceEmitter,
	s *MessageSwitch,
	m *qabalwrap.EnvelopedMessage) {
	spanEmitter.StartSpan(s.ServiceInstanceIdent, "queue-root-cert-req", "src-srv=%d", m.SourceServiceIdent)
	defer spanEmitter.FinishSpanSuccessWithoutMessage()
	s.rootCertificateRequests <- &rootCertRequest{
		spanEmitter:        spanEmitter,
		sourceServiceIdent: m.SourceServiceIdent,
	}
}

func handleRootCertificateRequest(s *MessageSwitch, rootCertReq *rootCertRequest) (err error) {
	requestSourceIdent := rootCertReq.sourceServiceIdent
	spanEmitter := rootCertReq.spanEmitter.StartSpan(s.ServiceInstanceIdent, "handle-root-cert-req", "req-src=%d", requestSourceIdent)
	if s.tlsCertProvider.RootCertKeyPair == nil {
		spanEmitter.FinishSpanSuccess("success: WARN: (handleRootCertificateRequest) root certificate is empty")
		return
	}
	respMsg := &qbw1grpcgen.RootCertificateAssignment{
		Timestamp: time.Now().Unix(),
		CertDer:   s.tlsCertProvider.RootCertKeyPair.CertDERBytes,
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(s.localServiceRef.SerialIdent, requestSourceIdent,
		qabalwrap.MessageContentRootCertificateAssignment, respMsg)
	if nil != err {
		spanEmitter.FinishSpanSuccess("success: WARN: (handleRootCertificateRequest) cannot marshal root certificate request: %v", err)
		return
	}
	if err = s.forwardClearEnvelopedMessage(spanEmitter, m); nil != err {
		spanEmitter.FinishSpanFailedLogf("(handleRootCertificateRequest) cannot emit enveloped message: %v", err)
	} else {
		spanEmitter.FinishSpanSuccess("(handleRootCertificateRequest) responed: destination=%d", requestSourceIdent)
	}
	return
}
