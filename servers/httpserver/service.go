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
}

func NewService(listenAddr string) (s *Service) {
	s = &Service{
		listenAddr:   listenAddr,
		hostHandlers: make(map[string]http.Handler),
	}
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
		http.NotFound(w, r)
		return
	}
	hnd.ServeHTTP(w, r)
}

// ReceiveMessage implement ServiceProvider interface.
func (s *Service) ReceiveMessage(envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	log.Printf("WARN: (HTTPServerService::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	return
}

// SetMessageSender implement ServiceProvider interface.
func (s *Service) SetMessageSender(messageSender *qabalwrap.MessageSender) {
	// TODO: implements
}

// UpdateHostTLSCertificates trigger host TLS update of service.
func (s *Service) UpdateHostTLSCertificates(waitGroup *sync.WaitGroup, tlsCerts []tls.Certificate) (err error) {
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
}

func (s *Service) Setup(certProvider qabalwrap.CertificateProvider) (err error) {
	hostNames := make([]string, 0, len(s.hostHandlers))
	for hostName := range s.hostHandlers {
		hostNames = append(hostNames, hostName)
	}
	_, err = certProvider.RegisterHostTLSCertificates(hostNames, s)
	return
}

func (s *Service) startImpl(waitGroup *sync.WaitGroup) (err error) {
	tlsCfg := &tls.Config{Certificates: s.tlsCerts}
	s.serverInst = &http.Server{
		Addr:      s.listenAddr,
		Handler:   s,
		TLSConfig: tlsCfg,
	}
	waitGroup.Add(1)
	go s.httpServerListenAndServeTLS(waitGroup)
	return
}

func (s *Service) Start(ctx context.Context, waitGroup *sync.WaitGroup) (err error) {
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
