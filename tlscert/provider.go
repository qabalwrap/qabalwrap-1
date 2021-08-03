package tlscert

import (
	"crypto/tls"
	"log"
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type subscribedHostTLSCerts struct {
	hostNameSerials map[string]int64
	certSubscriber  qabalwrap.CertificateSubscriber
}

// Provider of TLS certificate service.
type Provider struct {
	localCerts

	stateStore             *qabalwrap.StateStore
	primaryTLSCertProvider bool

	hostTLSCertSubscriptions []*subscribedHostTLSCerts
}

func (p *Provider) Init(
	dnCountry, dnOrganization string,
	stateStore *qabalwrap.StateStore,
	primaryTLSCertProvider bool) (err error) {
	p.stateStore = stateStore
	p.primaryTLSCertProvider = primaryTLSCertProvider
	ok, err := p.localCerts.load(p.stateStore)
	if !ok {
		p.localCerts.init(dnCountry, dnOrganization)
		if primaryTLSCertProvider {
			if err = p.localCerts.setupRootCA(); nil != err {
				return
			}
			if err = p.localCerts.save(p.stateStore); nil != err {
				return
			}
		}
	}
	return
}

func (p *Provider) updateSubscribedHostTLSCert(waitGroup *sync.WaitGroup, subscriptionRec *subscribedHostTLSCerts) (err error) {
	tlsCerts := make([]tls.Certificate, 0, len(subscriptionRec.hostNameSerials)+1)
	cert, err := MakeSelfSignedHostTLSCertificate(defaultCountry, defaultOrganization, defaultTLSHostAddress)
	if nil != err {
		log.Printf("ERROR: (updateSubscribedHostTLSCert) prepare default TLS certificate failed: %v", err)
		return
	}
	tlsCerts = append(tlsCerts, *cert)
	for hostN := range subscriptionRec.hostNameSerials {
		var cert *tls.Certificate
		var keyPair *CertificateKeyPair
		if keyPair, err = p.localCerts.prepareHostKeyPair(hostN, p.primaryTLSCertProvider); nil != err {
			log.Printf("ERROR: (updateSubscribedHostTLSCert) prepare TLS certificate failed [host=%s]: %v", hostN, err)
			return
		} else if keyPair != nil {
			cert = keyPair.TLSCertificate(p.RootCertKeyPair)
			subscriptionRec.hostNameSerials[hostN] = keyPair.Certificate.SerialNumber.Int64()
		} else {
			if cert, err = MakeSelfSignedHostTLSCertificate(p.Country, p.Organization, hostN); nil != err {
				log.Printf("ERROR: (updateSubscribedHostTLSCert) generate self-signed TLS certificate failed [host=%s]: %v", hostN, err)
				return
			}
			subscriptionRec.hostNameSerials[hostN] = 0
			log.Printf("INFO: (updateSubscribedHostTLSCert) use self-signed TLS certificate [host=%s]", hostN)
		}
		tlsCerts = append(tlsCerts, *cert)
	}
	if err = subscriptionRec.certSubscriber.UpdateHostTLSCertificates(waitGroup, tlsCerts); nil != err {
		log.Printf("ERROR: (updateSubscribedHostTLSCert) update certificate failed: %v", err)
	} else {
		log.Print("INFO: (updateSubscribedHostTLSCert) update certificate complete.")
	}
	return
}

func (p *Provider) updateAllHostTLSCert(waitGroup *sync.WaitGroup) (err error) {
	for _, subscriptionRec := range p.hostTLSCertSubscriptions {
		if err = p.updateSubscribedHostTLSCert(waitGroup, subscriptionRec); nil != err {
			return
		}
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		log.Printf("ERROR: (updateAllHostTLSCert) cannot save certificate pool: %v", err)
	}
	return
}

// PostSetup should be invoke at maintenance thread in setup stage.
func (p *Provider) PostSetup(waitGroup *sync.WaitGroup) (err error) {
	if err = p.updateAllHostTLSCert(waitGroup); nil != err {
		log.Printf("ERROR: (PostSetup) update all host TLS certificate failed: %v", err)
	}
	return
}

// UpdateRootCertificate set given certificate as root certificate and update registered subscribers.
func (p *Provider) UpdateRootCertificate(waitGroup *sync.WaitGroup, certKeyPair *CertificateKeyPair) (err error) {
	changed, err := p.updateRootCert(certKeyPair)
	if nil != err {
		log.Printf("ERROR: (UpdateRootCertificate) update root certificate failed: %v", err)
		return
	}
	if !changed {
		log.Printf("INFO: (UpdateRootCertificate) not change: changed=%v", changed)
		return
	}
	if err = p.updateAllHostTLSCert(waitGroup); nil != err {
		log.Printf("ERROR: (UpdateRootCertificate) update all host TLS cert failed: %v", err)
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		log.Printf("ERROR: (UpdateRootCertificate) cannot save certificate pool: %v", err)
	}
	log.Print("TRACE: (UpdateRootCertificate) update completed.")
	return
}

// UpdateHostCertificate associate given certificate with given host name and invoke TLS certificate update.
func (p *Provider) UpdateHostCertificate(waitGroup *sync.WaitGroup, hostName string, certKeyPair *CertificateKeyPair) (err error) {
	p.localCerts.setHostKeyPair(hostName, certKeyPair)
	for _, subscriptionRec := range p.hostTLSCertSubscriptions {
		if _, ok := subscriptionRec.hostNameSerials[hostName]; !ok {
			continue
		}
		if err = p.updateSubscribedHostTLSCert(waitGroup, subscriptionRec); nil != err {
			return
		}
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		log.Printf("ERROR: (UpdateHostCertificate) cannot save certificate pool: %v", err)
	}
	log.Printf("TRACE: (UpdateHostCertificate) update completed [%s].", hostName)
	return
}

// CollectSelfSignedHosts get hostnames with self-signed certificate issued.
func (p *Provider) CollectSelfSignedHosts() (hostNames []string) {
	c := make(map[string]struct{})
	for _, subscriptionRec := range p.hostTLSCertSubscriptions {
		for hostN, certSn := range subscriptionRec.hostNameSerials {
			if certSn != 0 {
				log.Printf("TRACE: (Provider::CollectSelfSignedHosts) not self-signed certificate: %s", hostN)
				continue
			}
			c[hostN] = struct{}{}
		}
	}
	hostNames = make([]string, 0, len(c))
	for hostN := range c {
		hostNames = append(hostNames, hostN)
	}
	return
}

func (p *Provider) PrepareQBw1HostCertificateAssignment(hostName string) (resp *qbw1grpcgen.HostCertificateAssignment, err error) {
	keyPair, err := p.localCerts.prepareHostKeyPair(hostName, p.primaryTLSCertProvider)
	if nil != err {
		log.Printf("ERROR: (PrepareQBw1HostCertificateAssignment) prepare TLS certificate failed [host=%s]: %v", hostName, err)
		return
	}
	if keyPair != nil {
		resp = keyPair.QBw1HostCertificateAssignment(hostName)
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		log.Printf("ERROR: (PrepareQBw1HostCertificateAssignment) cannot save certificate pool: %v", err)
	}
	return
}

// RegisterHostTLSCertificates implement CertificateProvider interface.
// Should only invoke at maintenance thread in setup stage.
func (p *Provider) RegisterHostTLSCertificates(
	hostNames []string,
	certSubscriber qabalwrap.CertificateSubscriber) (hostTLSCertWatchTrackIdent int, err error) {
	hostTLSCertWatchTrackIdent = len(p.hostTLSCertSubscriptions)
	subscriptionRec := &subscribedHostTLSCerts{
		hostNameSerials: make(map[string]int64),
		certSubscriber:  certSubscriber,
	}
	for _, hostN := range hostNames {
		subscriptionRec.hostNameSerials[hostN] = 0
	}
	p.hostTLSCertSubscriptions = append(p.hostTLSCertSubscriptions, subscriptionRec)
	return
}
