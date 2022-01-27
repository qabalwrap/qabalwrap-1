package httpaccess

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type serverAccessChannel struct {
	baseRelayProvider

	ctx context.Context
}

func newHTTPServeAccessChannel(ctx context.Context, sharedSecretText string, messageBufferCount int) (provider *serverAccessChannel, err error) {
	p := &serverAccessChannel{
		ctx: ctx,
	}
	if err = p.initBaseRelayProvider(sharedSecretText, messageBufferCount); nil != err {
		return
	}
	provider = p
	return
}

func (p *serverAccessChannel) serveBinary(spanEmitter *qabalwrap.TraceEmitter, w http.ResponseWriter, r *http.Request) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "server-access-ch-bin")
	if r.Method != http.MethodPost {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider::serveBinary) wrong http method (remote=%s): %v", r.RemoteAddr, r.Method)
		httpBadRequest(w, r)
		return
	}
	collectTimeout := slowEmptyMessageCollectTimeout
	if dispatchedMessageCount, err := p.dispatchMessages(spanEmitter, r.Body); nil != err {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider::serveBinary) having error on import payload (remote=%s): %v", r.RemoteAddr, err)
		httpBadRequest(w, r)
		return
	} else if dispatchedMessageCount > 0 {
		// log.Printf("TRACE: (HTTPServeAccessProvider::serveBinary) dispatched %d.", dispatchedMessageCount)
		collectTimeout = fastEmptyMessageCollectTimeout
	}
	resultPayload, _, err := p.packMessages(r.Context(), spanEmitter, collectTimeout)
	if nil != err {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider::serveBinary) having error on packaging payload (remote=%s): %v", r.RemoteAddr, err)
		http.Error(w, "500 internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(resultPayload)), 10))
	w.WriteHeader(http.StatusOK)
	w.Write(resultPayload)
	spanEmitter.FinishSpan("success")
}

func (p *serverAccessChannel) serveText(spanEmitter *qabalwrap.TraceEmitter, w http.ResponseWriter, r *http.Request) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "server-access-ch-txt")
	if r.Method != http.MethodPost {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider::serveText) wrong http method (remote=%s): %v", r.RemoteAddr, r.Method)
		httpBadRequest(w, r)
		return
	}
	b64decoder := base64.NewDecoder(base64.StdEncoding, r.Body)
	collectTimeout := slowEmptyMessageCollectTimeout
	if dispatchedMessageCount, err := p.dispatchMessages(spanEmitter, b64decoder); nil != err {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider::serveText) having error on import payload (remote=%s): %v", r.RemoteAddr, err)
		httpBadRequest(w, r)
		return
	} else if dispatchedMessageCount > 0 {
		// log.Printf("TRACE: (HTTPServeAccessProvider::serveText) dispatched %d.", dispatchedMessageCount)
		collectTimeout = fastEmptyMessageCollectTimeout
	}
	resultBinaries, _, err := p.packMessages(r.Context(), spanEmitter, collectTimeout)
	if nil != err {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider::serveText) having error on packaging payload (remote=%s): %v", r.RemoteAddr, err)
		http.Error(w, "500 internal error", http.StatusInternalServerError)
		return
	}
	resultPayload := make([]byte, base64.StdEncoding.EncodedLen(len(resultBinaries)))
	base64.StdEncoding.Encode(resultPayload, resultBinaries)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(resultPayload)), 10))
	w.WriteHeader(http.StatusOK)
	w.Write(resultPayload)
	spanEmitter.FinishSpan("success")
}

func (p *serverAccessChannel) Start(ctx context.Context, waitGroup *sync.WaitGroup, spanEmitter *qabalwrap.TraceEmitter) (err error) {
	return
}

func (p *serverAccessChannel) BlockingEmitMessage(spanEmitter *qabalwrap.TraceEmitter, rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	// log.Printf("TRACE: (HTTPServeAccessChannel::EmitMessage) blocking s=%d, d=%d, hop=%d", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.RemainHops)
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "http-access-server-block-emit")
	err = p.blockingEmitMessage(p.ctx, spanEmitter, rawMessage)
	spanEmitter.FinishSpanCheckErr(err)
	return
}

func (p *serverAccessChannel) NonblockingEmitMessage(spanEmitter *qabalwrap.TraceEmitter, rawMessage *qabalwrap.EnvelopedMessage) (emitSuccess bool) {
	// log.Printf("TRACE: (HTTPServeAccessChannel::EmitMessage) non-blocking s=%d, d=%d, hop=%d", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.RemainHops)
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "http-access-server-nonblock-emit")
	emitSuccess = p.nonblockingEmitMessage(p.ctx, spanEmitter, rawMessage)
	spanEmitter.FinishSpanCheckBool(emitSuccess)
	return
}

type HTTPServeAccessProvider struct {
	qabalwrap.ServiceBase

	accessChannels []*serverAccessChannel

	diagnosisEmitter *qabalwrap.DiagnosisEmitter
}

func NewHTTPServeAccessProvider(accessChannelSize int) (p *HTTPServeAccessProvider) {
	p = &HTTPServeAccessProvider{
		accessChannels: make([]*serverAccessChannel, 0, accessChannelSize),
	}
	return
}

// AddAccessChannel create new access channel in access provider.
// Must only invoke at setup stage.
func (p *HTTPServeAccessProvider) AddAccessChannel(ctx context.Context, channelIndex int, sharedSecretText string, messageBufferCount int) (relayProvider qabalwrap.RelayProvider, err error) {
	if channelIndex != len(p.accessChannels) {
		err = fmt.Errorf("unmatch channel index: given=%d, available=%d", channelIndex, len(p.accessChannels))
		return
	}
	ch, err := newHTTPServeAccessChannel(ctx, sharedSecretText, messageBufferCount)
	if nil != err {
		return
	}
	p.accessChannels = append(p.accessChannels, ch)
	return ch, nil
}

func (p *HTTPServeAccessProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	spanEmitter := p.diagnosisEmitter.StartTrace(p.ServiceInstanceIdent, "http-serve-access-provider", "url-path=%s", r.URL.Path)
	reqPath := r.URL.Path
	if len(reqPath) < 5 {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider) bad path: remote=%s, path=%v.", r.RemoteAddr, reqPath)
		http.NotFound(w, r)
		return
	}
	chIndex := int(reqPath[1] - '0')
	if (chIndex < 0) || (chIndex > len(p.accessChannels)) {
		spanEmitter.FinishSpanLogError("failed: (HTTPServeAccessProvider) bad channel index: remote=%s, path=%v, ch-index=%d.", r.RemoteAddr, reqPath, chIndex)
		http.NotFound(w, r)
		return
	}
	accessChRef := p.accessChannels[chIndex]
	routeChar := reqPath[3]
	switch routeChar {
	case 'b':
		accessChRef.serveBinary(spanEmitter, w, r)
	case 't':
		accessChRef.serveText(spanEmitter, w, r)
	}
	spanEmitter.FinishSpan("success")
}

// Setup prepare provider for operation.
// Should only invoke at maintenance thread in setup stage.
func (p *HTTPServeAccessProvider) Setup(
	serviceInstIdent qabalwrap.ServiceInstanceIdentifier,
	diagnosisEmitter *qabalwrap.DiagnosisEmitter,
	certProvider qabalwrap.CertificateProvider) (err error) {
	p.ServiceInstanceIdent = serviceInstIdent
	p.diagnosisEmitter = diagnosisEmitter
	for _, c := range p.accessChannels {
		c.baseRelayProvider.serviceInstIdent = serviceInstIdent + "-baserelay-s"
		c.diagnosisEmitter = diagnosisEmitter
	}
	return
}

// ReceiveMessage implement ServiceProvider interface.
func (p *HTTPServeAccessProvider) ReceiveMessage(spanEmitter *qabalwrap.TraceEmitter, rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	log.Printf("WARN: (HTTPServeAccessProvider::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	return
}

// RelayProviders return associated relay providers if available.
// Return nil if this service provider does not support relay service.
func (p *HTTPServeAccessProvider) RelayProviders() (relayProviders []qabalwrap.RelayProvider) {
	relayProviders = make([]qabalwrap.RelayProvider, len(p.accessChannels))
	for idx, c := range p.accessChannels {
		relayProviders[idx] = c
	}
	return
}
