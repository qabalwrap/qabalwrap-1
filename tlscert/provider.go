package tlscert

import (
	"crypto/tls"
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

	serviceInstIdent qabalwrap.ServiceInstanceIdentifier

	stateStore             *qabalwrap.StateStore
	primaryTLSCertProvider bool

	hostTLSCertSubscriptions []*subscribedHostTLSCerts
}

func (p *Provider) Init(
	serviceInstIdent qabalwrap.ServiceInstanceIdentifier,
	dnCountry, dnOrganization string,
	stateStore *qabalwrap.StateStore,
	primaryTLSCertProvider bool) (err error) {
	p.serviceInstIdent = serviceInstIdent
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

func (p *Provider) updateSubscribedHostTLSCert(waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter, subscriptionRec *subscribedHostTLSCerts) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "update-subscribed-host-tls-cert")
	tlsCerts := make([]tls.Certificate, 0, len(subscriptionRec.hostNameSerials)+1)
	cert, err := MakeSelfSignedHostTLSCertificate(defaultCountry, defaultOrganization, defaultTLSHostAddress)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(updateSubscribedHostTLSCert) prepare default TLS certificate failed: %v", err)
		return
	}
	tlsCerts = append(tlsCerts, *cert)
	for hostN := range subscriptionRec.hostNameSerials {
		var cert *tls.Certificate
		var keyPair *CertificateKeyPair
		if keyPair, err = p.localCerts.prepareHostKeyPair(hostN, p.primaryTLSCertProvider); nil != err {
			spanEmitter.FinishSpanFailedLogf("(updateSubscribedHostTLSCert) prepare TLS certificate failed [host=%s]: %v", hostN, err)
			return
		} else if keyPair != nil {
			cert = keyPair.TLSCertificate(p.RootCertKeyPair)
			subscriptionRec.hostNameSerials[hostN] = keyPair.Certificate.SerialNumber.Int64()
		} else {
			if cert, err = MakeSelfSignedHostTLSCertificate(p.Country, p.Organization, hostN); nil != err {
				spanEmitter.FinishSpanFailedLogf("(updateSubscribedHostTLSCert) generate self-signed TLS certificate failed [host=%s]: %v", hostN, err)
				return
			}
			subscriptionRec.hostNameSerials[hostN] = 0
			spanEmitter.EventInfo("(updateSubscribedHostTLSCert) use self-signed TLS certificate [host=%s]", hostN)
		}
		tlsCerts = append(tlsCerts, *cert)
	}
	if err = subscriptionRec.certSubscriber.UpdateHostTLSCertificates(waitGroup, spanEmitter, tlsCerts); nil != err {
		spanEmitter.FinishSpanFailedLogf("(updateSubscribedHostTLSCert) update certificate failed: %v", err)
	} else {
		spanEmitter.FinishSpanSuccess("(updateSubscribedHostTLSCert) update certificate complete.")
	}
	return
}

func (p *Provider) updateAllHostTLSCert(waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "update-all-host-tls-cert")
	for _, subscriptionRec := range p.hostTLSCertSubscriptions {
		if err = p.updateSubscribedHostTLSCert(waitGroup, spanEmitter, subscriptionRec); nil != err {
			spanEmitter.FinishSpanFailed("failed: cannot update: %v", err)
			return
		}
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		spanEmitter.FinishSpanFailedLogf("(updateAllHostTLSCert) cannot save certificate pool: %v", err)
	} else {
		spanEmitter.FinishSpanSuccessWithoutMessage()
	}
	return
}

// PostSetup should be invoke at maintenance thread in setup stage.
func (p *Provider) PostSetup(waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "tls-provider-post-setup")
	if err = p.updateAllHostTLSCert(waitGroup, spanEmitter); nil != err {
		spanEmitter.FinishSpanFailedLogf("(PostSetup) update all host TLS certificate failed: %v", err)
	} else {
		spanEmitter.FinishSpanSuccessWithoutMessage()
	}
	return
}

// UpdateRootCertificate set given certificate as root certificate and update registered subscribers.
func (p *Provider) UpdateRootCertificate(waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter, certKeyPair *CertificateKeyPair) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "tls-provider-update-root-cert")
	changed, err := p.updateRootCert(spanEmitter, certKeyPair)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(UpdateRootCertificate) update root certificate failed: %v", err)
		return
	}
	if !changed {
		spanEmitter.FinishSpanSuccess("(UpdateRootCertificate) not change: changed=%v", changed)
		return
	}
	updateSuccess := true
	if err = p.updateAllHostTLSCert(waitGroup, spanEmitter); nil != err {
		spanEmitter.EventError("(UpdateRootCertificate) update all host TLS cert failed: %v", err)
		updateSuccess = false
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		spanEmitter.EventError("(UpdateRootCertificate) cannot save certificate pool: %v", err)
		updateSuccess = false
	}
	if updateSuccess {
		spanEmitter.FinishSpanSuccessWithoutMessage()
	} else {
		spanEmitter.FinishSpanFailedWithoutMessage()
	}
	return
}

// UpdateHostCertificate associate given certificate with given host name and invoke TLS certificate update.
func (p *Provider) UpdateHostCertificate(waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter, hostName string, certKeyPair *CertificateKeyPair) (err error) {
	spanEmitter = spanEmitter.StartSpan(p.serviceInstIdent, "tls-provider-update-host-cert", "hostname=%s", hostName)
	p.localCerts.setHostKeyPair(hostName, certKeyPair)
	for _, subscriptionRec := range p.hostTLSCertSubscriptions {
		if _, ok := subscriptionRec.hostNameSerials[hostName]; !ok {
			continue
		}
		if err = p.updateSubscribedHostTLSCert(waitGroup, spanEmitter, subscriptionRec); nil != err {
			spanEmitter.FinishSpanFailedLogf("cannot update subscribed host cert: %v", err)
			return
		}
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		spanEmitter.FinishSpanFailedLogf("(UpdateHostCertificate) cannot save certificate pool: %v", err)
	} else {
		spanEmitter.FinishSpanSuccess("(UpdateHostCertificate) update completed [%s].", hostName)
	}
	return
}

// CollectSelfSignedHosts get hostnames with self-signed certificate issued.
func (p *Provider) CollectSelfSignedHosts(spanEmitter *qabalwrap.TraceEmitter) (hostNames []string) {
	c := make(map[string]struct{})
	for _, subscriptionRec := range p.hostTLSCertSubscriptions {
		for hostN, certSn := range subscriptionRec.hostNameSerials {
			if certSn != 0 {
				// spanEmitter.EventInfof("(Provider::CollectSelfSignedHosts) not self-signed certificate: %s", hostN)
				continue
			}
			c[hostN] = struct{}{}
		}
	}
	hostNames = make([]string, 0, len(c))
	for hostN := range c {
		hostNames = append(hostNames, hostN)
		spanEmitter.EventInfo("(Provider::CollectSelfSignedHosts) self-signed certificate: %s", hostN)
	}
	spanEmitter.EventInfo("(Provider::CollectSelfSignedHosts) found %d self-signed certificate")
	return
}

func (p *Provider) PrepareQBw1HostCertificateAssignment(spanEmitter *qabalwrap.TraceEmitter, hostName string) (resp *qbw1grpcgen.HostCertificateAssignment, err error) {
	spanEmitter = spanEmitter.StartSpan(p.serviceInstIdent, "tls-provider-prepare-host-cert-assignment", "hostname=%s", hostName)
	keyPair, err := p.localCerts.prepareHostKeyPair(hostName, p.primaryTLSCertProvider)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(PrepareQBw1HostCertificateAssignment) prepare TLS certificate failed [host=%s]: %v", hostName, err)
		return
	}
	if keyPair != nil {
		resp = keyPair.QBw1HostCertificateAssignment(hostName)
	}
	if err = p.saveWhenModified(p.stateStore); nil != err {
		spanEmitter.FinishSpanFailedLogf("(PrepareQBw1HostCertificateAssignment) cannot save certificate pool: %v", err)
	} else {
		spanEmitter.FinishSpanSuccessWithoutMessage()
	}
	return
}

// RegisterHostTLSCertificates implement CertificateProvider interface.
// Should only invoke at maintenance thread in setup stage.
func (p *Provider) RegisterHostTLSCertificates(
	spanEmitter *qabalwrap.TraceEmitter,
	hostNames []string,
	certSubscriber qabalwrap.CertificateSubscriber) (hostTLSCertWatchTrackIdent int, err error) {
	hostTLSCertWatchTrackIdent = len(p.hostTLSCertSubscriptions)
	subscriptionRec := &subscribedHostTLSCerts{
		hostNameSerials: make(map[string]int64),
		certSubscriber:  certSubscriber,
	}
	for _, hostN := range hostNames {
		subscriptionRec.hostNameSerials[hostN] = 0
		spanEmitter.EventInfo("(RegisterHostTLSCertificates) subscribe to [%s]", hostN)
	}
	p.hostTLSCertSubscriptions = append(p.hostTLSCertSubscriptions, subscriptionRec)
	return
}
