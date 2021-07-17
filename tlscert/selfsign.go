package tlscert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
)

// MakeSelfSignedHostTLSCertificate create a copy of self-signed host TLS certificate.
func MakeSelfSignedHostTLSCertificate(dnCountry, dnOrganization, hostDNSName string) (tlsCert *tls.Certificate, err error) {
	serverTpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:      []string{dnCountry},
			Organization: []string{dnOrganization},
			CommonName:   hostDNSName,
		},
		DNSNames:    []string{hostDNSName},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(selfSignedCertValidDuration),
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
		log.Printf("ERROR: cannot generate key for host (self-signed) [%s]: %v", hostDNSName, err)
		return
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &serverTpl, &serverTpl, &priv.PublicKey, priv)
	if err != nil {
		log.Printf("ERROR: cannot create self-signed certificate for host [%s]: %v", hostDNSName, err)
		return
	}
	tlsCert = &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
	}
	return
}
