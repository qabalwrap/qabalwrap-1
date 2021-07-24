package messageswitch

import (
	"log"
	"time"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

func queueRootCertificateRequest(s *MessageSwitch, m *qabalwrap.EnvelopedMessage) {
	s.rootCertificateRequests <- m.SourceServiceIdent
}

func handleRootCertificateRequest(s *MessageSwitch, requestSourceIdent int) (err error) {
	if s.tlsCertProvider.RootCertKeyPair == nil {
		log.Print("WARN: (handleRootCertificateRequest) root certificate is empty")
		return
	}
	respMsg := &qbw1grpcgen.RootCertificateAssignment{
		Timestamp: time.Now().Unix(),
		CertDer:   s.tlsCertProvider.RootCertKeyPair.CertDERBytes,
	}
	m, err := qabalwrap.MarshalIntoClearEnvelopedMessage(s.localServiceRef.SerialIdent, requestSourceIdent,
		qabalwrap.MessageContentRootCertificateAssignment, respMsg)
	if nil != err {
		log.Printf("WARN: (handleRootCertificateRequest) cannot marshal root certificate request: %v", err)
		return
	}
	if err = s.forwardClearEnvelopedMessage(m); nil != err {
		log.Printf("ERROR: (handleRootCertificateRequest) cannot emit enveloped message: %v", err)
	}
	return
}
