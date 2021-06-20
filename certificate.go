package qabalwrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

const (
	commonNameRootCA            = "QabalWrap Root CA"
	expireAheadDuration         = time.Hour * 7 * 24
	rootCAValidDuration         = time.Hour * 24 * 366 * 20
	hostCertValidDuration       = time.Hour * 24 * 366
	selfSignedCertValidDuration = time.Hour * 8
)

const certificateRequestExpireSeconds = 180

var errNotValidRootCA = errors.New("not valid root CA")
var errCertificateRequestTimeout = errors.New("cert request timeout")

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

type CertificateManager struct {
	lck                 sync.RWMutex
	Country             string                         `json:"dn_c"`
	Organization        string                         `json:"dn_o"`
	CurrentSerialNumber int64                          `json:"current_serial"`
	RootCertKeyPair     *CertificateKeyPair            `json:"root_ca"`
	HostCertKeyPairs    map[string]*CertificateKeyPair `json:"host_certs"`
}

func NewCertificateManager(dnCountry, dnOrganization string) (certMgr *CertificateManager) {
	certMgr = &CertificateManager{
		Country:             dnCountry,
		Organization:        dnOrganization,
		CurrentSerialNumber: 10,
		HostCertKeyPairs:    make(map[string]*CertificateKeyPair),
	}
	return
}

func (certMgr *CertificateManager) allocateSerialNumber() int64 {
	n := time.Now().UnixNano()
	if n <= certMgr.CurrentSerialNumber {
		n = certMgr.CurrentSerialNumber + 1
	}
	certMgr.CurrentSerialNumber = n
	return n
}

// SetupRootCA generate root certificate and key pair.
// By calling this method make this certificate manager a root CA.
func (certMgr *CertificateManager) SetupRootCA() (err error) {
	certMgr.lck.Lock()
	defer certMgr.lck.Unlock()
	rootTpl := x509.Certificate{
		SerialNumber: big.NewInt(certMgr.allocateSerialNumber()),
		Subject: pkix.Name{
			Country:      []string{certMgr.Country},
			Organization: []string{certMgr.Organization},
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
	if certMgr.RootCertKeyPair, err = newCertificateKeyPair(certBytes, priv); nil != err {
		log.Printf("ERROR: cannot unpack certificate for root CA: %v", err)
	}
	return
}

// SetupHostKeyPair generate certificate and key pair for given host DNS name.
// Given hostDNSName must normalize before invoke.
// Existed one will be overwrite.
func (certMgr *CertificateManager) SetupHostKeyPair(hostDNSName string) (err error) {
	certMgr.lck.Lock()
	defer certMgr.lck.Unlock()
	if certMgr.RootCertKeyPair.PrivateKey == nil {
		return errNotValidRootCA
	}
	serverTpl := x509.Certificate{
		SerialNumber: big.NewInt(certMgr.allocateSerialNumber()),
		Subject: pkix.Name{
			Country:      []string{certMgr.Country},
			Organization: []string{certMgr.Organization},
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
	certBytes, err := x509.CreateCertificate(rand.Reader, &serverTpl, certMgr.RootCertKeyPair.Certificate, &priv.PublicKey, certMgr.RootCertKeyPair.PrivateKey)
	if err != nil {
		log.Printf("ERROR: cannot create certificate for host [%s]: %v", hostDNSName, err)
		return
	}
	hostCert, err := newCertificateKeyPair(certBytes, priv)
	if nil != err {
		log.Printf("ERROR: cannot unpack certificate for host [%s]: %v", hostDNSName, err)
		return
	}
	certMgr.HostCertKeyPairs[hostDNSName] = hostCert
	return
}

func (certMgr *CertificateManager) SetHostKeyPair(hostDNSName string, hostCertKeyPair *CertificateKeyPair) {
	certMgr.lck.Lock()
	defer certMgr.lck.Unlock()
	certMgr.HostCertKeyPairs[hostDNSName] = hostCertKeyPair
}

// HaveRootCertificate check if root certificate existed.
func (certMgr *CertificateManager) HaveRootCertificate() (rootCertExisted bool) {
	certMgr.lck.Lock()
	defer certMgr.lck.Unlock()
	return (certMgr.RootCertKeyPair != nil) && (certMgr.RootCertKeyPair.Certificate.NotAfter.After(time.Now()))
}

// UpdateRootCertificate set root certificate to given one.
func (certMgr *CertificateManager) UpdateRootCertificate(externalRootCert *CertificateKeyPair) (changed bool, err error) {
	certMgr.lck.Lock()
	defer certMgr.lck.Unlock()
	if certMgr.RootCertKeyPair != nil {
		if certMgr.RootCertKeyPair.Certificate.Equal(externalRootCert.Certificate) {
			return
		}
		if externalRootCert.Certificate.NotAfter.Before(certMgr.RootCertKeyPair.Certificate.NotAfter) {
			return
		}
	}
	certMgr.RootCertKeyPair = externalRootCert
	return true, nil
}

func (certMgr *CertificateManager) MakeSelfSignedHostTLSCertificate(hostDNSName string) (tlsCert *tls.Certificate, err error) {
	serverTpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:      []string{certMgr.Country},
			Organization: []string{certMgr.Organization},
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

// GetHostTLSCertificate fetch host TLS certificate.
func (certMgr *CertificateManager) GetHostTLSCertificate(hostDNSName string) (tlsCert *tls.Certificate) {
	certMgr.lck.RLock()
	defer certMgr.lck.RUnlock()
	hostCertKeyPair := certMgr.HostCertKeyPairs[hostDNSName]
	if hostCertKeyPair == nil {
		return
	}
	if time.Until(hostCertKeyPair.Certificate.NotAfter) < expireAheadDuration {
		return
	}
	return hostCertKeyPair.TLSCertificate(certMgr.RootCertKeyPair)
}

// GetHostKeyPair fetch host certificate key pair.
func (certMgr *CertificateManager) GetHostKeyPair(hostDNSName string) (certKeyPair *CertificateKeyPair) {
	certMgr.lck.RLock()
	defer certMgr.lck.RUnlock()
	hostCertKeyPair := certMgr.HostCertKeyPairs[hostDNSName]
	if hostCertKeyPair == nil {
		return
	}
	if time.Until(hostCertKeyPair.Certificate.NotAfter) < expireAheadDuration {
		return
	}
	certKeyPair = hostCertKeyPair
	return
}

type CertificateRequest struct {
	sync.Mutex

	RequestIdent       int32
	AllocatedTimestamp int64

	certKeyPair *CertificateKeyPair
}

func (req *CertificateRequest) allocate(requestIndex int) {
	var rndKey [2]byte
	io.ReadFull(rand.Reader, rndKey[:])
	d0 := uint32(binary.LittleEndian.Uint16(rndKey[:]))
	req.RequestIdent = int32((d0<<16)&0x7FFF0000 | (uint32(requestIndex) & 0xFFFF))
	atomic.StoreInt64(&req.AllocatedTimestamp, time.Now().Unix())
	req.Lock()
	req.certKeyPair = nil
}

func (req *CertificateRequest) isAvailable() bool {
	if t := atomic.LoadInt64(&req.AllocatedTimestamp); t == 0 {
		return true
	}
	return false
}

func (req *CertificateRequest) isExpired(boundTimestamp int64) bool {
	if t := atomic.LoadInt64(&req.AllocatedTimestamp); (t > 0) && (t < boundTimestamp) {
		return true
	}
	return false
}

func (req *CertificateRequest) reset() {
	req.RequestIdent = -1
	req.certKeyPair = nil
	atomic.StoreInt64(&req.AllocatedTimestamp, 0)
}

func (req *CertificateRequest) Wait() (certKeyPair *CertificateKeyPair, err error) {
	// req.Lock()
	// req.CertDERBytes = nil
	req.Lock()
	defer req.Unlock()
	if certKeyPair = req.certKeyPair; certKeyPair == nil {
		err = errCertificateRequestTimeout
	}
	req.reset()
	return
}

func (req *CertificateRequest) Release(certKeyPair *CertificateKeyPair) {
	req.certKeyPair = certKeyPair
	req.Unlock()
}

func (req *CertificateRequest) forceRelease() {
	req.Unlock()
}

type CertificateRequestQueue struct {
	sync.Mutex

	Requests []*CertificateRequest
}

func (q *CertificateRequestQueue) Init(queueSize int) {
	q.Requests = make([]*CertificateRequest, queueSize)
	for idx := 0; idx < len(q.Requests); idx++ {
		q.Requests[idx] = &CertificateRequest{}
	}
}

func (q *CertificateRequestQueue) GetRequest(requestIdent int32) *CertificateRequest {
	reqIndex := int(requestIdent & 0xFFFF)
	q.Lock()
	defer q.Unlock()
	if (reqIndex < 0) || (reqIndex >= len(q.Requests)) {
		log.Printf("ERROR: (CertificateRequestQueue::GetRequest) index out of range: %d / %d", reqIndex, requestIdent)
		return nil
	}
	result := q.Requests[reqIndex]
	if result.RequestIdent != requestIdent {
		log.Printf("ERROR: (CertificateRequestQueue::GetRequest) identifier not match: %d / %d vs. %d", reqIndex, requestIdent, result.RequestIdent)
		return nil
	}
	return result
}

func (q *CertificateRequestQueue) DropExpiredRequests() {
	q.Lock()
	defer q.Unlock()
	boundaryTimestamp := time.Now().Unix() - certificateRequestExpireSeconds
	expiredReqIndexs := make([]int, 0, 8)
	for reqIndex, reqInst := range q.Requests {
		if !reqInst.isExpired(boundaryTimestamp) {
			continue
		}
		reqInst.forceRelease()
		expiredReqIndexs = append(expiredReqIndexs, reqIndex)
	}
	for _, reqIndex := range expiredReqIndexs {
		log.Printf("TRACE: (CertificateRequestQueue::DropExpiredRequests) detach expired request instance index %d.", reqIndex)
		q.Requests[reqIndex] = &CertificateRequest{}
	}
}

func (q *CertificateRequestQueue) AllocateRequest() *CertificateRequest {
	q.Lock()
	defer q.Unlock()
	for reqIndex, reqInst := range q.Requests {
		if !reqInst.isAvailable() {
			continue
		}
		reqInst.allocate(reqIndex)
		log.Printf("TRACE: (CertificateRequestQueue::AllocateRequest) allocated instance index %d.", reqIndex)
		return reqInst
	}
	boundaryTimestamp := time.Now().Unix() - certificateRequestExpireSeconds
	targetExpiredReqIndex := -1
	for reqIndex, reqInst := range q.Requests {
		if reqInst.isExpired(boundaryTimestamp) {
			targetExpiredReqIndex = reqIndex
			reqInst.forceRelease()
			log.Printf("TRACE: (CertificateRequestQueue::AllocateRequest) detach expired request instance index %d.", reqIndex)
			break
		}
	}
	if targetExpiredReqIndex != -1 {
		reqInst := &CertificateRequest{}
		q.Requests[targetExpiredReqIndex] = reqInst
		reqInst.allocate(targetExpiredReqIndex)
		log.Printf("TRACE: (CertificateRequestQueue::AllocateRequest) allocated instance index %d (replacing expired instance).", targetExpiredReqIndex)
		return reqInst
	}
	log.Print("ERROR: (CertificateRequestQueue::AllocateRequest) cannot allocate certificate request instance,")
	return nil
}

func (q *CertificateRequestQueue) Stop() {
	q.Lock()
	defer q.Unlock()
	for reqIndex, reqInst := range q.Requests {
		if reqInst.isAvailable() {
			continue
		}
		reqInst.forceRelease()
		log.Printf("WARN: (CertificateRequestQueue::Stop) force releasing instance index %d.", reqIndex)
	}
}
