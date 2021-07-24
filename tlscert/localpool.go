package tlscert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

const localCertsContentIdent = qabalwrap.ContentIdentCertificateManager

type localCerts struct {
	Country             string                         `json:"dn_c"`
	Organization        string                         `json:"dn_o"`
	CurrentSerialNumber int64                          `json:"current_serial"`
	RootCertKeyPair     *CertificateKeyPair            `json:"root_ca"`
	HostCertKeyPairs    map[string]*CertificateKeyPair `json:"host_certs"`

	lastModifyTimestamp int64
}

func (lc *localCerts) init(dnCountry, dnOrganization string) {
	*lc = localCerts{
		Country:             dnCountry,
		Organization:        dnOrganization,
		CurrentSerialNumber: 10,
		HostCertKeyPairs:    make(map[string]*CertificateKeyPair),
	}
}

func (lc *localCerts) load(stateStore *qabalwrap.StateStore) (ok bool, err error) {
	return stateStore.Unmarshal(localCertsContentIdent, lc)
}

func (lc *localCerts) save(stateStore *qabalwrap.StateStore) (err error) {
	if err = stateStore.Marshal(localCertsContentIdent, lc); nil != err {
		return
	}
	lc.lastModifyTimestamp = 0
	return
}

func (lc *localCerts) saveWhenModified(stateStore *qabalwrap.StateStore) (err error) {
	if lc.lastModifyTimestamp == 0 {
		return
	}
	return lc.save(stateStore)
}

func (lc *localCerts) allocateSerialNumber() int64 {
	n := time.Now().UnixNano()
	if n <= lc.CurrentSerialNumber {
		n = lc.CurrentSerialNumber + 1
	}
	lc.CurrentSerialNumber = n
	return n
}

// setupRootCA generate root certificate and key pair.
// By calling this method make this certificate manager a root CA.
func (lc *localCerts) setupRootCA() (err error) {
	rootTpl := x509.Certificate{
		SerialNumber: big.NewInt(lc.allocateSerialNumber()),
		Subject: pkix.Name{
			Country:      []string{lc.Country},
			Organization: []string{lc.Organization},
			CommonName:   commonNameRootCA,
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(rootCAValidDuration),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		// IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("ERROR: cannot generate key for root CA: %v", err)
		return
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &rootTpl, &rootTpl, &priv.PublicKey, priv)
	if err != nil {
		log.Printf("ERROR: cannot create certificate for root CA: %v", err)
		return
	}
	if lc.RootCertKeyPair, err = newCertificateKeyPair(certBytes, priv); nil != err {
		log.Printf("ERROR: cannot unpack certificate for root CA: %v", err)
	}
	lc.lastModifyTimestamp = time.Now().Unix()
	return
}

// setupHostKeyPair generate certificate and key pair for given host DNS name.
// Given hostDNSName must normalize before invoke.
// Existed one will be overwrite.
func (lc *localCerts) setupHostKeyPair(hostDNSName string) (err error) {
	if lc.RootCertKeyPair.PrivateKey == nil {
		return errNotValidRootCA
	}
	serverTpl := x509.Certificate{
		SerialNumber: big.NewInt(lc.allocateSerialNumber()),
		Subject: pkix.Name{
			Country:      []string{lc.Country},
			Organization: []string{lc.Organization},
			CommonName:   hostDNSName,
		},
		DNSNames:    []string{hostDNSName},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(hostCertValidDuration),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// BasicConstraintsValid: true,
		IsCA: false,
		// MaxPathLen:            2,
		MaxPathLenZero: true,
		// IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("ERROR: cannot generate key for host [%s]: %v", hostDNSName, err)
		return
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &serverTpl, lc.RootCertKeyPair.Certificate, &priv.PublicKey, lc.RootCertKeyPair.PrivateKey)
	if err != nil {
		log.Printf("ERROR: cannot create certificate for host [%s]: %v", hostDNSName, err)
		return
	}
	hostCert, err := newCertificateKeyPair(certBytes, priv)
	if nil != err {
		log.Printf("ERROR: cannot unpack certificate for host [%s]: %v", hostDNSName, err)
		return
	}
	lc.HostCertKeyPairs[hostDNSName] = hostCert
	lc.lastModifyTimestamp = time.Now().Unix()
	return
}

func (lc *localCerts) setHostKeyPair(hostDNSName string, hostCertKeyPair *CertificateKeyPair) {
	lc.HostCertKeyPairs[hostDNSName] = hostCertKeyPair
	lc.lastModifyTimestamp = time.Now().Unix()
}

// HaveRootCertificate check if root certificate existed.
func (lc *localCerts) HaveRootCertificate() (rootCertExisted bool) {
	return (lc.RootCertKeyPair != nil) && (lc.RootCertKeyPair.Certificate.NotAfter.After(time.Now()))
}

// updateRootCert set root certificate to given one.
func (lc *localCerts) updateRootCert(externalRootCert *CertificateKeyPair) (changed bool, err error) {
	if lc.RootCertKeyPair != nil {
		if lc.RootCertKeyPair.Certificate.Equal(externalRootCert.Certificate) {
			return
		}
		if externalRootCert.Certificate.NotAfter.Before(lc.RootCertKeyPair.Certificate.NotAfter) {
			return
		}
	}
	lc.RootCertKeyPair = externalRootCert
	return true, nil
}

// getHostTLSCertificate fetch host TLS certificate.
/*
func (lc *localCerts) getHostTLSCertificate(hostDNSName string) (tlsCert *tls.Certificate) {
	hostCertKeyPair := lc.HostCertKeyPairs[hostDNSName]
	if hostCertKeyPair == nil {
		return
	}
	if time.Until(hostCertKeyPair.Certificate.NotAfter) < expireAheadDuration {
		return
	}
	return hostCertKeyPair.TLSCertificate(lc.RootCertKeyPair)
}
*/

// getHostKeyPair fetch host certificate key pair.
func (lc *localCerts) getHostKeyPair(hostDNSName string) (certKeyPair *CertificateKeyPair) {
	hostCertKeyPair := lc.HostCertKeyPairs[hostDNSName]
	if hostCertKeyPair == nil {
		return
	}
	if time.Until(hostCertKeyPair.Certificate.NotAfter) < expireAheadDuration {
		return
	}
	certKeyPair = hostCertKeyPair
	return
}

// prepareHostKeyPair fetch host certificate key pair or setup key pair if setupWhenUnavailable is enabled.
func (lc *localCerts) prepareHostKeyPair(hostDNSName string, setupWhenUnavailable bool) (certKeyPair *CertificateKeyPair, err error) {
	if certKeyPair = lc.getHostKeyPair(hostDNSName); certKeyPair != nil {
		return
	}
	if !setupWhenUnavailable {
		return
	}
	if err = lc.setupHostKeyPair(hostDNSName); nil != err {
		return
	}
	certKeyPair = lc.getHostKeyPair(hostDNSName)
	return
}
