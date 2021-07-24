package messageswitch

import (
	"log"
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
	qw1tlscert "github.com/qabalwrap/qabalwrap-1/tlscert"
)

func queueHostCertificateAssignment(s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	if s.primarySwitch {
		log.Printf("ERROR: (queueHostCertificateAssignment) primary switch does not accept host certificate assignment (src=%d, dest=%d)",
			m.SourceServiceIdent, m.DestinationServiceIdent)
		err = ErrNotSupportedOperation
		return
	}
	var a qbw1grpcgen.HostCertificateAssignment
	if err = m.Unmarshal(&a); nil != err {
		log.Printf("ERROR: (queueHostCertificateAssignment) unmarshal assignment failed: %v", err)
		return
	}
	hostCertKey, err := qw1tlscert.NewCertificateKeyPairFromQBw1HostCertificateAssignment(&a)
	if nil != err {
		log.Printf("ERROR: (queueHostCertificateAssignment) unmarshal root certificate failed: %v", err)
		return
	}
	r := &hostCertAssignment{
		hostName:    a.HostDNSName,
		certKeyPair: hostCertKey,
	}
	s.hostCertificateAssignments <- r
	return
}

func handleHostCertificateAssignment(waitgroup *sync.WaitGroup, s *MessageSwitch, r *hostCertAssignment) (err error) {
	if err = s.tlsCertProvider.UpdateHostCertificate(waitgroup, r.hostName, r.certKeyPair); nil != err {
		log.Printf("ERROR: (handleHostCertificateAssignment) update host cert failed [%s]: %v", r.hostName, err)
	}
	return
}
