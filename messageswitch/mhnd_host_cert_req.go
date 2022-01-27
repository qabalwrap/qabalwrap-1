package messageswitch

import (
	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

func queueHostCertificateRequest(spanEmitter *qabalwrap.TraceEmitter, s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "queue-host-cert-req")
	if !s.primarySwitch {
		spanEmitter.FinishSpanFailedLogf("(queueHostCertificateRequest) non-primary switch does not accept certificate request (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		return ErrNotSupportedOperation
	}
	var a qbw1grpcgen.HostCertificateRequest
	if err = m.Unmarshal(&a); nil != err {
		spanEmitter.FinishSpanFailedLogf("(queueHostCertificateRequest) unmarshal assignment failed: %v", err)
		return
	}
	hostName := a.HostDNSName
	spanEmitter.EventInfo("(queueHostCertificateRequest) request certificate for [%s] from %d", hostName, m.SourceServiceIdent)
	req := &hostCertRequest{
		spanEmitter:       spanEmitter,
		sourceSerialIdent: m.SourceServiceIdent,
		hostName:          hostName,
	}
	s.hostCertificateRequests <- req
	return
}

func handleHostCertificateRequest(s *MessageSwitch, req *hostCertRequest) (err error) {
	spanEmitter := req.spanEmitter.StartSpanWithoutMessage(s.ServiceInstanceIdent, "handle-host-cert-req")
	resp, err := s.tlsCertProvider.PrepareQBw1HostCertificateAssignment(spanEmitter, req.hostName)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(handleHostCertificateRequest) request certificate for [%s] failed: %v", req.hostName, err)
		return
	}
	if resp == nil {
		spanEmitter.FinishSpanFailedLogf("(handleHostCertificateRequest) request certificate for [%s] result empty", req.hostName)
		return ErrNotSupportedOperation
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(s.localServiceRef.SerialIdent, req.sourceSerialIdent,
		qabalwrap.MessageContentHostCertificateAssignment, resp)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(handleHostCertificateRequest) cannot marshal root certificate request: %v", err)
		return
	}
	if err = s.forwardClearEnvelopedMessage(spanEmitter, m); nil != err {
		spanEmitter.FinishSpanFailedLogf("(handleHostCertificateRequest) cannot emit enveloped message: %v", err)
	} else {
		spanEmitter.FinishSpanSuccess("(handleHostCertificateRequest) responed: hostname=%s, destination=%d", req.hostName, req.sourceSerialIdent)
	}
	return
}
