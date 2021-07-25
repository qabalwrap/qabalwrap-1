package messageswitch

import (
	"log"
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

func queueRootCertificateAssignment(s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	if s.primarySwitch {
		log.Printf("ERROR: (queueRootCertificateAssignment) primary switch does not accept root certificate assignment (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		err = ErrNotSupportedOperation
		return
	}
	var a qbw1grpcgen.RootCertificateAssignment
	if err = m.Unmarshal(&a); nil != err {
		log.Printf("ERROR: (queueRootCertificateAssignment) unmarshal assignment failed: %v", err)
		return
	}
	rootCertKey, err := qw1tlscert.NewCertificateKeyPairFromQBw1RootCertificateAssignment(&a)
	if nil != err {
		log.Printf("ERROR: (queueRootCertificateAssignment) unmarshal root certificate failed: %v", err)
		return
	}
	s.rootCertificateAssignment <- rootCertKey
	return
}

func handleRootCertificateAssignment(waitgroup *sync.WaitGroup, s *MessageSwitch, k *qw1tlscert.CertificateKeyPair) (err error) {
	log.Print("INFO: (handleRootCertificateAssignment) have root cert assignment.")
	if err = s.tlsCertProvider.UpdateRootCertificate(waitgroup, k); nil != err {
		log.Printf("ERROR: (handleRootCertificateAssignment) update root cert failed: %v", err)
	}
	return
}
