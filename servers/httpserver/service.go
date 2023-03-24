package httpserver

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"sync"
	"time"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

// Service implement HTTP server service.
type Service struct {
	qabalwrap.ServiceBase

	serverInst    *http.Server
	serverRunning bool

	listenAddr string

	hostHandlers  map[string]http.Handler
	maxHostLength int

	tlsCerts []tls.Certificate

	linkStats        linkStatSlice
	diagnosisEmitter *qabalwrap.DiagnosisEmitter
}

func NewService(listenAddr string, maxLinkCount int) (s *Service) {
	s = &Service{
		listenAddr:   listenAddr,
		hostHandlers: make(map[string]http.Handler),
	}
	s.linkStats.init(maxLinkCount)
	return
}

func (s *Service) AddHostHandler(host string, handler http.Handler) {
	host = normalizeHTTPHost(host)
	if hostLen := len(host); hostLen > s.maxHostLength {
		s.maxHostLength = hostLen
	}
	s.hostHandlers[host] = handler
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHTTPHost(r.Host)
	// TODO: logging access target
	hnd, ok := s.hostHandlers[host]
	if !ok {
		w.Header().Set("Strict-Transport-Security", "max-age=172800")
		http.NotFound(w, r)
		return
	}
	linkIndex, ok := s.linkStats.allocateLink(r)
	if !ok {
		http.Error(w, "all link unavailable", http.StatusServiceUnavailable)
		return
	}
	defer s.linkStats.releaseLink(linkIndex)
	hnd.ServeHTTP(w, r)
}

// ReceiveMessage implement ServiceProvider interface.
func (s *Service) ReceiveMessage(spanEmitter *qabalwrap.TraceEmitter, envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	log.Printf("WARN: (HTTPServerService::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	return
}

// UpdateHostTLSCertificates trigger host TLS update of service.
func (s *Service) UpdateHostTLSCertificates(waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter, tlsCerts []tls.Certificate) (err error) {
	s.tlsCerts = tlsCerts
	if s.serverRunning {
		s.Stop()
		err = s.startImpl(waitGroup)
	}
	return
}

func (s *Service) httpServerListenAndServeTLS(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	log.Printf("INFO: (HTTPServerService::httpServerListenAndServeTLS) listen to: %s", s.listenAddr)
	if err := s.serverInst.ListenAndServeTLS("", ""); nil != err {
		log.Printf("INFO: (HTTPServerService::httpServerListenAndServeTLS) http server stopped (listen-address: %s): %v", s.listenAddr, err)
	}
	s.serverInst = nil
	s.serverRunning = false
}

func (s *Service) Setup(
	serviceInstIdent qabalwrap.ServiceInstanceIdentifier,
	diagnosisEmitter *qabalwrap.DiagnosisEmitter,
	certProvider qabalwrap.CertificateProvider) (err error) {
	s.ServiceInstanceIdent = serviceInstIdent
	spanEmitter := diagnosisEmitter.StartTraceWithoutMessage(s.ServiceInstanceIdent, "servers-http-start-setup")
	defer spanEmitter.FinishSpanSuccessWithoutMessage()
	hostNames := make([]string, 0, len(s.hostHandlers))
	for hostName := range s.hostHandlers {
		hostNames = append(hostNames, hostName)
	}
	_, err = certProvider.RegisterHostTLSCertificates(spanEmitter, hostNames, s)
	s.diagnosisEmitter = diagnosisEmitter
	return
}

func (s *Service) startImpl(waitGroup *sync.WaitGroup) (err error) {
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: s.tlsCerts,
		CipherSuites: []uint16{
			// AEADs w/ ECDHE
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			// AEADs w/o ECDHE
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
	}
	s.serverInst = &http.Server{
		Addr:              s.listenAddr,
		ReadHeaderTimeout: time.Second * 10,
		Handler:           s,
		TLSConfig:         tlsCfg,
	}
	waitGroup.Add(1)
	s.serverRunning = true
	go s.httpServerListenAndServeTLS(waitGroup)
	return
}

func (s *Service) Start(ctx context.Context, waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter) (err error) {
	return s.startImpl(waitGroup)
}

func (s *Service) Stop() {
	if s.serverInst == nil {
		log.Printf("INFO: (HTTPServerService::Stop) server instance not exist (listen-address: %s)", s.listenAddr)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.serverInst.Shutdown(ctx); nil != err {
		log.Printf("INFO: (HTTPServerService::Stop) server stopped (listen-address: %s): %v", s.listenAddr, err)
	} else {
		log.Printf("INFO: (HTTPServerService::Stop) server stopped (listen-address: %s)", s.listenAddr)
	}
}
