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

func (p *serverAccessChannel) serveBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveBinary) wrong http method (remote=%s): %v", r.RemoteAddr, r.Method)
		httpBadRequest(w, r)
		return
	}
	collectTimeout := slowEmptyMessageCollectTimeout
	if dispatchedMessageCount, err := p.dispatchMessages(r.Body); nil != err {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveBinary) having error on import payload (remote=%s): %v", r.RemoteAddr, err)
		httpBadRequest(w, r)
		return
	} else if dispatchedMessageCount > 0 {
		// log.Printf("TRACE: (HTTPServeAccessProvider::serveBinary) dispatched %d.", dispatchedMessageCount)
		collectTimeout = fastEmptyMessageCollectTimeout
	}
	resultPayload, _, err := p.packMessages(r.Context(), collectTimeout)
	if nil != err {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveBinary) having error on packaging payload (remote=%s): %v", r.RemoteAddr, err)
		http.Error(w, "500 internal error", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(resultPayload)), 10))
	w.WriteHeader(http.StatusOK)
	w.Write(resultPayload)
}

func (p *serverAccessChannel) serveText(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveText) wrong http method (remote=%s): %v", r.RemoteAddr, r.Method)
		httpBadRequest(w, r)
		return
	}
	b64decoder := base64.NewDecoder(base64.StdEncoding, r.Body)
	collectTimeout := slowEmptyMessageCollectTimeout
	if dispatchedMessageCount, err := p.dispatchMessages(b64decoder); nil != err {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveText) having error on import payload (remote=%s): %v", r.RemoteAddr, err)
		httpBadRequest(w, r)
		return
	} else if dispatchedMessageCount > 0 {
		// log.Printf("TRACE: (HTTPServeAccessProvider::serveText) dispatched %d.", dispatchedMessageCount)
		collectTimeout = fastEmptyMessageCollectTimeout
	}
	resultBinaries, _, err := p.packMessages(r.Context(), collectTimeout)
	if nil != err {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveText) having error on packaging payload (remote=%s): %v", r.RemoteAddr, err)
		http.Error(w, "500 internal error", http.StatusInternalServerError)
	}
	resultPayload := make([]byte, base64.StdEncoding.EncodedLen(len(resultBinaries)))
	base64.StdEncoding.Encode(resultPayload, resultBinaries)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(resultPayload)), 10))
	w.WriteHeader(http.StatusOK)
	w.Write(resultPayload)
}

func (p *serverAccessChannel) Start(ctx context.Context, waitGroup *sync.WaitGroup) (err error) {
	return
}

func (p *serverAccessChannel) BlockingEmitMessage(rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	// log.Printf("TRACE: (HTTPServeAccessChannel::EmitMessage) blocking s=%d, d=%d, hop=%d", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.RemainHops)
	return p.blockingEmitMessage(p.ctx, rawMessage)
}

func (p *serverAccessChannel) NonblockingEmitMessage(rawMessage *qabalwrap.EnvelopedMessage) (emitSuccess bool) {
	// log.Printf("TRACE: (HTTPServeAccessChannel::EmitMessage) non-blocking s=%d, d=%d, hop=%d", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.RemainHops)
	return p.nonblockingEmitMessage(p.ctx, rawMessage)
}

type HTTPServeAccessProvider struct {
	qabalwrap.ServiceBase

	accessChannels []*serverAccessChannel
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
	reqPath := r.URL.Path
	if len(reqPath) < 5 {
		log.Printf("WARN: (HTTPServeAccessProvider) bad path: remote=%s, path=%v.", r.RemoteAddr, reqPath)
		http.NotFound(w, r)
		return
	}
	chIndex := int(reqPath[1] - '0')
	if (chIndex < 0) || (chIndex > len(p.accessChannels)) {
		log.Printf("WARN: (HTTPServeAccessProvider) bad channel index: remote=%s, path=%v, ch-index=%d.", r.RemoteAddr, reqPath, chIndex)
		http.NotFound(w, r)
		return
	}
	accessChRef := p.accessChannels[chIndex]
	routeChar := reqPath[3]
	switch routeChar {
	case 'b':
		accessChRef.serveBinary(w, r)
	case 't':
		accessChRef.serveText(w, r)
	}
}

// ReceiveMessage implement ServiceProvider interface.
func (p *HTTPServeAccessProvider) ReceiveMessage(rawMessage *qabalwrap.EnvelopedMessage) (err error) {
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
