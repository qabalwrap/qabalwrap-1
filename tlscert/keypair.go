package tlscert

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type certificateKeyPair struct {
	CertDERText    string `json:"cert"`
	PrivateKeyText string `json:"priv"`
}

type CertificateKeyPair struct {
	CertDERBytes []byte
	Certificate  *x509.Certificate
	PrivateKey   *rsa.PrivateKey
}

func newCertificateKeyPair(certDERBytes []byte, privateKey *rsa.PrivateKey) (k *CertificateKeyPair, err error) {
	certInst, err := x509.ParseCertificate(certDERBytes)
	if nil != err {
		return
	}
	k = &CertificateKeyPair{
		CertDERBytes: certDERBytes,
		Certificate:  certInst,
		PrivateKey:   privateKey,
	}
	return
}

// NewCertificateKeyPairFromQBw1RootCertificateAssignment create certificate key pair from root certificate assignment.
func NewCertificateKeyPairFromQBw1RootCertificateAssignment(a *qbw1grpcgen.RootCertificateAssignment) (k *CertificateKeyPair, err error) {
	return newCertificateKeyPair(a.CertDer, nil)
}

func newCertificateKeyPairFromQBw1HostCertificateAssignment(a *qbw1grpcgen.HostCertificateAssignment) (k *CertificateKeyPair, err error) {
	certDERBytes := a.CertDer
	certInst, err := x509.ParseCertificate(certDERBytes)
	if nil != err {
		return
	}
	var privateKey *rsa.PrivateKey
	if privateKey, err = x509.ParsePKCS1PrivateKey(a.PrivateKey); nil != err {
		return
	}
	k = &CertificateKeyPair{
		CertDERBytes: certDERBytes,
		Certificate:  certInst,
		PrivateKey:   privateKey,
	}
	return
}

func (k *CertificateKeyPair) TLSCertificate(rootKeyPair *CertificateKeyPair) (tlsCert *tls.Certificate) {
	tlsCert = &tls.Certificate{
		Certificate: [][]byte{k.CertDERBytes, rootKeyPair.CertDERBytes},
		PrivateKey:  k.PrivateKey,
	}
	return
}

// MarshalJSON implement json.Marshaler interface,
func (k *CertificateKeyPair) MarshalJSON() ([]byte, error) {
	var privateKeyText string
	if k.PrivateKey != nil {
		privateKeyDER := x509.MarshalPKCS1PrivateKey(k.PrivateKey)
		privateKeyText = base64.StdEncoding.EncodeToString(privateKeyDER)
	}
	aux := certificateKeyPair{
		CertDERText:    base64.StdEncoding.EncodeToString(k.CertDERBytes),
		PrivateKeyText: privateKeyText,
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implement json.Unmarshaler interface.
func (k *CertificateKeyPair) UnmarshalJSON(data []byte) (err error) {
	var aux certificateKeyPair
	if err = json.Unmarshal(data, &aux); nil != err {
		return
	}
	if k.CertDERBytes, err = base64.StdEncoding.DecodeString(aux.CertDERText); nil != err {
		return
	}
	if k.Certificate, err = x509.ParseCertificate(k.CertDERBytes); nil != err {
		return
	}
	if aux.PrivateKeyText != "" {
		var privateKeyDER []byte
		if privateKeyDER, err = base64.StdEncoding.DecodeString(aux.PrivateKeyText); nil != err {
			return
		}
		if k.PrivateKey, err = x509.ParsePKCS1PrivateKey(privateKeyDER); nil != err {
			return
		}
	}
	return
}

func (k *CertificateKeyPair) QBw1HostCertificateAssignment(requestIdent int32) (resp *qbw1grpcgen.HostCertificateAssignment) {
	var privateKeyDER []byte
	if k.PrivateKey != nil {
		privateKeyDER = x509.MarshalPKCS1PrivateKey(k.PrivateKey)
	}
	resp = &qbw1grpcgen.HostCertificateAssignment{
		RequestIdent: requestIdent,
		CertDer:      k.CertDERBytes,
		PrivateKey:   privateKeyDER,
	}
	return
}
