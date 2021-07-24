package messageswitch

import (
	"log"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

func queueHostCertificateRequest(s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	if !s.primarySwitch {
		log.Printf("ERROR: (queueHostCertificateRequest) non-primary switch does not accept certificate request (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		return ErrNotSupportedOperation
	}
	var a qbw1grpcgen.HostCertificateRequest
	if err = m.Unmarshal(&a); nil != err {
		log.Printf("ERROR: (queueHostCertificateRequest) unmarshal assignment failed: %v", err)
		return
	}
	hostName := a.HostDNSName
	log.Printf("INFO: (queueHostCertificateRequest) request certificate for [%s]", hostName)
	req := &hostCertRequest{
		sourceSerialIdent: m.SourceServiceIdent,
		hostName:          hostName,
	}
	s.hostCertificateRequests <- req
	return
}

func handleHostCertificateRequest(s *MessageSwitch, req *hostCertRequest) (err error) {
	resp, err := s.tlsCertProvider.PrepareQBw1HostCertificateAssignment(req.hostName)
	if nil != err {
		log.Printf("ERROR: (handleHostCertificateRequest) request certificate for [%s] failed: %v", req.hostName, err)
		return
	}
	if resp == nil {
		log.Printf("ERROR: (handleHostCertificateRequest) request certificate for [%s] result empty", req.hostName)
		return ErrNotSupportedOperation
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(s.localServiceRef.SerialIdent, req.sourceSerialIdent,
		qabalwrap.MessageContentRootCertificateAssignment, resp)
	if nil != err {
		log.Printf("WARN: (handleHostCertificateRequest) cannot marshal root certificate request: %v", err)
		return
	}
	if err = s.forwardClearEnvelopedMessage(m); nil != err {
		log.Printf("ERROR: (handleHostCertificateRequest) cannot emit enveloped message: %v", err)
	}
	return
}
