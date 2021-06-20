package qabalwrap

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

func normalizeHTTPHost(host string) string {
	i := len(host)
	b := i - 6
	if b < 0 {
		b = 0
	}
	for i--; i >= b; i-- {
		if host[i] == ':' {
			return strings.ToLower(host[:i])
		}
	}
	return strings.ToLower(host)
}

type HTTPServerService struct {
	serverInst *http.Server

	listenAddr string

	hostHandlers  map[string]http.Handler
	maxHostLength int
}

func NewHTTPServerService(listenAddr string) (s *HTTPServerService) {
	s = &HTTPServerService{
		listenAddr:   listenAddr,
		hostHandlers: make(map[string]http.Handler),
	}
	return
}

func (s *HTTPServerService) AddHostHandler(host string, handler http.Handler) {
	host = normalizeHTTPHost(host)
	if hostLen := len(host); hostLen > s.maxHostLength {
		s.maxHostLength = hostLen
	}
	s.hostHandlers[host] = handler
}

func (s *HTTPServerService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
func (s *HTTPServerService) ReceiveMessage(rawMessage *RawMessage) (err error) {
	log.Printf("WARN: (HTTPServerService::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	return
}

// SetMessageSender implement ServiceProvider interface.
func (s *HTTPServerService) SetMessageSender(messageSender *MessageSender) {
	// TODO: implements
}

func (s *HTTPServerService) httpServerListenAndServeTLS(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	log.Printf("INFO: (HTTPServerService::httpServerListenAndServeTLS) listen to: %s", s.listenAddr)
	if err := s.serverInst.ListenAndServeTLS("", ""); nil != err {
		log.Printf("INFO: (HTTPServerService::httpServerListenAndServeTLS) http server stopped (listen-address: %s): %v", s.listenAddr, err)
	}
	s.serverInst = nil
}

func (s *HTTPServerService) Start(waitGroup *sync.WaitGroup, certProvider CertificateProvider) (err error) {
	hostNames := make([]string, 0, len(s.hostHandlers))
	for hostName := range s.hostHandlers {
		hostNames = append(hostNames, hostName)
	}
	tlsCerts, err := certProvider.GetHostTLSCertificates(hostNames)
	if nil != err {
		return
	}
	tlsCfg := &tls.Config{Certificates: tlsCerts}
	s.serverInst = &http.Server{
		Addr:      s.listenAddr,
		Handler:   s,
		TLSConfig: tlsCfg,
	}
	waitGroup.Add(1)
	go s.httpServerListenAndServeTLS(waitGroup)
	return
}

func (s *HTTPServerService) Stop() {
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
