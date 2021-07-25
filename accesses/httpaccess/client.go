package httpaccess

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

const HTTPClientAccessProviderUserAgent = "qabalwrap-access/0.0.0"

type ClientExchangeMode int32

const (
	ClientUnknownExchangeMode ClientExchangeMode = iota
	ClientBinaryExchangeMode
	ClientTextExchangeMode
)

func (m ClientExchangeMode) MarshalText() (text []byte, err error) {
	switch m {
	case ClientBinaryExchangeMode:
		return []byte("binary"), nil
	case ClientTextExchangeMode:
		return []byte("text"), nil
	}
	return []byte("uknown"), nil
}

func (m *ClientExchangeMode) UnmarshalText(text []byte) (err error) {
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "b":
		fallthrough
	case "bin":
		fallthrough
	case "binary":
		*m = ClientBinaryExchangeMode
	case "t":
		fallthrough
	case "txt":
		fallthrough
	case "text":
		*m = ClientTextExchangeMode
	default:
		*m = ClientUnknownExchangeMode
	}
	return
}

type HTTPClientAccessProvider struct {
	qabalwrap.ServiceBase
	baseRelayProvider

	transportInst *http.Transport
	clientInst    *http.Client

	ctx context.Context

	targetServerBaseURL string
	httpHostOverride    string
	exchangeMode        ClientExchangeMode
}

func NewHTTPClientAccessProvider(ctx context.Context, sharedSecretText string, messageBufferCount int,
	targetServerURL *url.URL, httpHostOverride string,
	channelIndex int, exchangeMode ClientExchangeMode,
	skipTLSVerify bool) (provider *HTTPClientAccessProvider, err error) {
	if (channelIndex < 0) || (channelIndex > 9) {
		err = fmt.Errorf("channel index out of range: %d", channelIndex)
		return
	}
	p := &HTTPClientAccessProvider{
		ctx:                 ctx,
		targetServerBaseURL: targetServerURL.Scheme + "://" + targetServerURL.Host + "/" + strconv.FormatInt(int64(channelIndex), 10),
		httpHostOverride:    httpHostOverride,
		exchangeMode:        exchangeMode,
	}
	if err = p.initBaseRelayProvider(sharedSecretText, messageBufferCount); nil != err {
		return
	}
	p.transportInst = http.DefaultTransport.(*http.Transport).Clone()
	if skipTLSVerify {
		p.transportInst.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	p.clientInst = &http.Client{
		Transport: p.transportInst,
	}
	provider = p
	return
}

func (p *HTTPClientAccessProvider) exchangeInBinary(collectTimeout time.Duration) (exportedMessageCount, dispatchedMessageCount int, err error) {
	resultPayload, exportedMessageCount, err := p.packMessages(p.ctx, collectTimeout)
	if nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInBinary) having error on packaging payload: %v", err)
		return
	}
	targetURL := p.targetServerBaseURL + "/b/" + strconv.FormatInt(time.Now().UnixNano(), 16)
	payloadReader := bytes.NewReader(resultPayload)
	req, err := http.NewRequestWithContext(p.ctx, http.MethodPost, targetURL, payloadReader)
	if nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInBinary) cannot create request: %v", err)
		return
	}
	req.Header.Set("User-Agent", HTTPClientAccessProviderUserAgent)
	req.Header.Set("Content-Type", "application/octet-stream")
	if p.httpHostOverride != "" {
		req.Host = p.httpHostOverride
	}
	resp, err := p.clientInst.Do(req)
	if nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInBinary) error on emit request: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("request result is not 200: %d", resp.StatusCode)
		return
	}
	if dispatchedMessageCount, err = p.dispatchMessages(resp.Body); nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInBinary) having error on import payload: %v", err)
		return
	}
	// log.Printf("TRACE: (HTTPClientAccessProvider::exchangeInBinary) transmitted: up %d, down %d.", exportedMessageCount, dispatchedMessageCount)
	return
}

func (p *HTTPClientAccessProvider) exchangeInText(collectTimeout time.Duration) (exportedMessageCount, dispatchedMessageCount int, err error) {
	resultBinaries, exportedMessageCount, err := p.packMessages(p.ctx, collectTimeout)
	if nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInText) having error on packaging payload: %v", err)
		return
	}
	resultPayload := make([]byte, base64.StdEncoding.EncodedLen(len(resultBinaries)))
	base64.StdEncoding.Encode(resultPayload, resultBinaries)
	targetURL := p.targetServerBaseURL + "/t/" + strconv.FormatInt(time.Now().UnixNano(), 16)
	payloadReader := bytes.NewReader(resultPayload)
	req, err := http.NewRequestWithContext(p.ctx, http.MethodPost, targetURL, payloadReader)
	if nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInText) cannot create request: %v", err)
		return
	}
	req.Header.Set("User-Agent", HTTPClientAccessProviderUserAgent)
	req.Header.Set("Content-Type", "text/plain")
	if p.httpHostOverride != "" {
		req.Host = p.httpHostOverride
	}
	resp, err := p.clientInst.Do(req)
	if nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInText) error on emit request: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("request result is not 200: %d", resp.StatusCode)
		return
	}
	b64decoder := base64.NewDecoder(base64.StdEncoding, resp.Body)
	if dispatchedMessageCount, err = p.dispatchMessages(b64decoder); nil != err {
		log.Printf("ERROR: (HTTPClientAccessProvider::exchangeInText) having error on import payload: %v", err)
		return
	}
	// log.Printf("TRACE: (HTTPClientAccessProvider::exchangeInText) transmitted: up %d, down %d.", exportedMessageCount, dispatchedMessageCount)
	return
}

func (p *HTTPClientAccessProvider) exchangeLoop(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	collectTimeout := slowEmptyMessageCollectTimeout
	var failureCount int
	var currentSessionTimestamp int64
	for {
		var exportedMessageCount, dispatchedMessageCount int
		var err error
		switch p.exchangeMode {
		case ClientBinaryExchangeMode:
			exportedMessageCount, dispatchedMessageCount, err = p.exchangeInBinary(collectTimeout)
		case ClientTextExchangeMode:
			exportedMessageCount, dispatchedMessageCount, err = p.exchangeInText(collectTimeout)
		default:
			err = fmt.Errorf("unknown exchange mode: %v", p.exchangeMode)
		}
		// log.Printf("TRACE: (HTTPClientAccessProvider::exchangeLoop) exported=%d, dispatched=%d; err=%v.", exportedMessageCount, dispatchedMessageCount, err)
		if nil != err {
			log.Printf("ERROR: (HTTPClientAccessProvider::ExchangeLoop) exchange failed: %v", err)
			failureCount++
			currentSessionTimestamp = 0
		} else {
			failureCount = 0
			if currentSessionTimestamp == 0 {
				currentSessionTimestamp = time.Now().UnixNano()
				p.messageDispatcher.LinkEstablished()
			}
		}
		if p.ctx.Err() != nil {
			log.Print("INFO: (HTTPClientAccessProvider::exchangeLoop) exit loop.")
			return
		}
		if failureCount > 0 {
			delay := time.Minute * 10
			switch failureCount {
			case 1:
				delay = time.Second * 10
			case 2:
				delay = time.Second * 30
			case 3:
				delay = time.Minute
			case 4:
				delay = time.Minute * 3
			case 5:
				delay = time.Minute * 5
			}
			log.Printf("INFO: (HTTPClientAccessProvider::exchangeLoop) delay for positive failure count: %v", delay)
			time.Sleep(delay)
			log.Printf("INFO: (HTTPClientAccessProvider::exchangeLoop) left delay: %v", delay)
			p.clientInst.CloseIdleConnections()
			collectTimeout = slowEmptyMessageCollectTimeout
			continue
		}
		if (exportedMessageCount > 0) || (dispatchedMessageCount > 0) {
			collectTimeout = fastEmptyMessageCollectTimeout
		} else {
			collectTimeout = slowEmptyMessageCollectTimeout
		}
	}
}

func (p *HTTPClientAccessProvider) Start(ctx context.Context, waitGroup *sync.WaitGroup) (err error) {
	waitGroup.Add(1)
	go p.exchangeLoop(waitGroup)
	return
}

// ReceiveMessage implement ServiceProvider interface.
func (p *HTTPClientAccessProvider) ReceiveMessage(rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	log.Printf("WARN: (HTTPClientAccessProvider::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	return
}

func (p *HTTPClientAccessProvider) BlockingEmitMessage(rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	return p.blockingEmitMessage(p.ctx, rawMessage)
}

func (p *HTTPClientAccessProvider) NonblockingEmitMessage(rawMessage *qabalwrap.EnvelopedMessage) (emitSuccess bool) {
	return p.nonblockingEmitMessage(p.ctx, rawMessage)
}

// RelayProviders return associated relay providers if available.
// Return nil if this service provider does not support relay service.
func (p *HTTPClientAccessProvider) RelayProviders() (relayProviders []qabalwrap.RelayProvider) {
	relayProviders = []qabalwrap.RelayProvider{p}
	return
}
