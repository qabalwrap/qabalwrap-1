package qabalwrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

var errBinaryPayloadDecrypt = errors.New("decrypt failed")

func httpBadRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "400 bad request", http.StatusBadRequest)
}

type commonRelayProviderBase struct {
	sharedSecret      [32]byte
	messageBuffer     chan *RawMessage
	messageDispatcher *MessageDispatcher
}

func (p *commonRelayProviderBase) SetMessageDispatcher(dispatcher *MessageDispatcher) {
	p.messageDispatcher = dispatcher
}

func (p *commonRelayProviderBase) collectMessagesAsMuchAsPossible(ctx context.Context) (resultQueue []*RawMessage, resultSize int) {
	timer := time.NewTimer(nonEmptyRawMessageCollectTimeout)
	for resultSize < softPayloadSizeLimit {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case rawMsg := <-p.messageBuffer:
			resultQueue = append(resultQueue, rawMsg)
			resultSize += rawMsg.PackedLen()
		}
	}
	if !timer.Stop() {
		<-timer.C
	}
	return
}

func (p *commonRelayProviderBase) collectMessages(ctx context.Context, collectTimeout time.Duration) (resultQueue []*RawMessage, resultSize int) {
	startTimestamp := time.Now()
	if resultQueue, resultSize = p.collectMessagesAsMuchAsPossible(ctx); resultSize > 0 {
		return
	}
	for resultSize < softPayloadSizeLimit {
		if resultQueue, resultSize = p.collectMessagesAsMuchAsPossible(ctx); resultSize > 0 {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(startTimestamp) > collectTimeout {
			return
		}
	}
	return
}

// packMessages collect and encode waiting raw messages in given collect timeout.
func (p *commonRelayProviderBase) packMessages(ctx context.Context, collectTimeout time.Duration) (resultBinaries []byte, messageCount int, err error) {
	resultQueue, resultSize := p.collectMessages(ctx, collectTimeout)
	if ctx.Err() != nil {
		return
	}
	var buf []byte
	if resultSize == 0 {
		buf = make([]byte, 4)
	} else {
		buf = make([]byte, 0, resultSize)
		for _, rawMsg := range resultQueue {
			buf = rawMsg.Pack(buf)
		}
		messageCount = len(resultQueue)
	}
	result := make([]byte, sha256.Size+4+24, sha256.Size+4+24+len(buf)+secretbox.Overhead)
	var nonce [24]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::packMessages) cannot init nonce: %v", err)
		return
	}
	copy(result[sha256.Size+4:], nonce[:])
	result = secretbox.Seal(result, buf, &nonce, &p.sharedSecret)
	sizeReal := len(result) - (sha256.Size + 4)
	binary.LittleEndian.PutUint32(result[sha256.Size:], uint32(sizeReal))
	chksum := sha256.Sum256(result[sha256.Size:])
	copy(result, chksum[:])
	mask1 := binary.LittleEndian.Uint32(chksum[0:])
	mask2 := binary.LittleEndian.Uint32(chksum[8:])
	sizeRaw := uint32(sizeReal) ^ mask1 ^ mask2
	binary.LittleEndian.PutUint32(result[sha256.Size:], uint32(sizeRaw))
	resultBinaries = result
	return
}

func (p *commonRelayProviderBase) unpackMessages(b io.Reader) (payload []byte, err error) {
	var chksum [sha256.Size]byte
	var sizeBuf [4]byte
	var n int
	if n, err = io.ReadFull(b, chksum[:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::unpackMessages) not enough bytes for digest: %d, %v", n, err)
		return
	}
	if n, err = io.ReadFull(b, sizeBuf[:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::unpackMessages) not enough bytes for size: %d, %v", n, err)
		return
	}
	sizeRaw := binary.LittleEndian.Uint32(sizeBuf[:])
	mask1 := binary.LittleEndian.Uint32(chksum[0:])
	mask2 := binary.LittleEndian.Uint32(chksum[8:])
	sizeReal := int(sizeRaw ^ mask1 ^ mask2)
	if (sizeReal > hardPayloadSizeLimit) || (sizeReal < 24) {
		err = fmt.Errorf("exceed hard HTTP binary payload limit: %d", sizeReal)
		return
	}
	totalBuf := make([]byte, 4+sizeReal)
	binary.LittleEndian.PutUint32(totalBuf[0:], uint32(sizeReal))
	if n, err = io.ReadFull(b, totalBuf[4:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::unpackMessages) not enough bytes for payload: %d, expect=%d, %v", n, sizeReal, err)
		return
	}
	versum := sha256.Sum256(totalBuf)
	if chksum != versum {
		err = fmt.Errorf("invalid package checksum: %s vs. %s", base64.RawURLEncoding.EncodeToString(chksum[:]), base64.RawURLEncoding.EncodeToString(versum[:]))
	}
	var nonce [24]byte
	copy(nonce[:], totalBuf[4:])
	payloadBytes, ok := secretbox.Open(nil, totalBuf[4+24:], &nonce, &p.sharedSecret)
	if !ok {
		err = errBinaryPayloadDecrypt
		return
	}
	payload = payloadBytes
	return
}

func (p *commonRelayProviderBase) dispatchMessages(b io.Reader) (dispatchedMessageCount int, err error) {
	payload, err := p.unpackMessages(b)
	if nil != err {
		return
	}
	for len(payload) > 0 {
		var rawMsg *RawMessage
		if rawMsg, payload, err = UnpackRawMessage(payload); nil != err {
			log.Printf("ERROR: (commonRelayProviderBase::dispatchMessages) unpack into raw message failed: %v", err)
			return
		}
		if rawMsg != nil {
			p.messageDispatcher.DispatchRawMessage(rawMsg)
			dispatchedMessageCount++
		}
	}
	return
}

func (p *commonRelayProviderBase) initCommonRelayProviderBase(sharedSecretText string, messageBufferCount int) (err error) {
	if sharedSecretText == "" {
		if _, err = io.ReadFull(rand.Reader, p.sharedSecret[:]); nil != err {
			log.Printf("ERROR: (commonRelayProviderBase) cannot generate shared key: %v", err)
			return
		}
		log.Printf("INFO: (commonRelayProviderBase) shared key generated: [ %s ]",
			base64.RawURLEncoding.EncodeToString(p.sharedSecret[:]))
	} else {
		var buf []byte
		if buf, err = base64.RawURLEncoding.DecodeString(sharedSecretText); nil != err {
			log.Printf("ERROR: (commonRelayProviderBase) cannot unpack shared key: %v", err)
			return
		}
		if len(buf) < 32 {
			log.Printf("WARN: (commonRelayProviderBase) short shared key: %d (< 32)", len(buf))
		}
		copy(p.sharedSecret[:], buf)
	}
	p.messageBuffer = make(chan *RawMessage, messageBufferCount)
	return
}

func (p *commonRelayProviderBase) emitMessage(ctx context.Context, rawMessage *RawMessage) (err error) {
	select {
	case p.messageBuffer <- rawMessage:
		return
	default:
	}
	timer := time.NewTimer(emitRawMessageTimeout)
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = ErrEmitMessageTimeout
	case p.messageBuffer <- rawMessage:
	}
	if !timer.Stop() {
		<-timer.C
	}
	return
}

type HTTPServeAccessChannel struct {
	commonRelayProviderBase

	ctx context.Context
}

func NewHTTPServeAccessChannel(ctx context.Context, sharedSecretText string, messageBufferCount int) (provider *HTTPServeAccessChannel, err error) {
	p := &HTTPServeAccessChannel{
		ctx: ctx,
	}
	if err = p.initCommonRelayProviderBase(sharedSecretText, messageBufferCount); nil != err {
		return
	}
	provider = p
	return
}

func (p *HTTPServeAccessChannel) serveBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveBinary) wrong http method (remote=%s): %v", r.RemoteAddr, r.Method)
		httpBadRequest(w, r)
		return
	}
	collectTimeout := slowEmptyRawMessageCollectTimeout
	if dispatchedMessageCount, err := p.dispatchMessages(r.Body); nil != err {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveBinary) having error on import payload (remote=%s): %v", r.RemoteAddr, err)
		httpBadRequest(w, r)
		return
	} else if dispatchedMessageCount > 0 {
		// log.Printf("TRACE: (HTTPServeAccessProvider::serveBinary) dispatched %d.", dispatchedMessageCount)
		collectTimeout = fastEmptyRawMessageCollectTimeout
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

func (p *HTTPServeAccessChannel) serveText(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveText) wrong http method (remote=%s): %v", r.RemoteAddr, r.Method)
		httpBadRequest(w, r)
		return
	}
	b64decoder := base64.NewDecoder(base64.StdEncoding, r.Body)
	collectTimeout := slowEmptyRawMessageCollectTimeout
	if dispatchedMessageCount, err := p.dispatchMessages(b64decoder); nil != err {
		log.Printf("ERROR: (HTTPServeAccessProvider::serveText) having error on import payload (remote=%s): %v", r.RemoteAddr, err)
		httpBadRequest(w, r)
		return
	} else if dispatchedMessageCount > 0 {
		// log.Printf("TRACE: (HTTPServeAccessProvider::serveText) dispatched %d.", dispatchedMessageCount)
		collectTimeout = fastEmptyRawMessageCollectTimeout
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

func (p *HTTPServeAccessChannel) Start(waitGroup *sync.WaitGroup) {
}

func (p *HTTPServeAccessChannel) EmitMessage(rawMessage *RawMessage) (err error) {
	// log.Printf("TRACE: (HTTPServeAccessChannel::EmitMessage) s=%d, d=%d, hop=%d", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.RemainHops)
	return p.emitMessage(p.ctx, rawMessage)
}

type HTTPServeAccessProvider struct {
	accessChannels []*HTTPServeAccessChannel
}

func NewHTTPServeAccessProvider(accessChannels []*HTTPServeAccessChannel) (p *HTTPServeAccessProvider) {
	p = &HTTPServeAccessProvider{
		accessChannels: accessChannels,
	}
	return
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
func (p *HTTPServeAccessProvider) ReceiveMessage(rawMessage *RawMessage) (err error) {
	log.Printf("WARN: (HTTPClientAccessProvider::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	return
}

// SetMessageSender implement ServiceProvider interface.
func (p *HTTPServeAccessProvider) SetMessageSender(messageSender *MessageSender) {
	// TODO: implements
}

const HTTPClientAccessProviderUserAgent = "qabalwrap-access/0.0.0"

type HTTPClientAccessExchangeMode int32

const (
	HTTPClientAccessUnknownMode HTTPClientAccessExchangeMode = iota
	HTTPClientAccessBinaryMode
	HTTPClientAccessTextMode
)

func (m HTTPClientAccessExchangeMode) MarshalText() (text []byte, err error) {
	switch m {
	case HTTPClientAccessBinaryMode:
		return []byte("binary"), nil
	case HTTPClientAccessTextMode:
		return []byte("text"), nil
	}
	return []byte("uknown"), nil
}

func (m *HTTPClientAccessExchangeMode) UnmarshalText(text []byte) (err error) {
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "b":
		fallthrough
	case "bin":
		fallthrough
	case "binary":
		*m = HTTPClientAccessBinaryMode
	case "t":
		fallthrough
	case "txt":
		fallthrough
	case "text":
		*m = HTTPClientAccessTextMode
	default:
		*m = HTTPClientAccessUnknownMode
	}
	return
}

type HTTPClientAccessProvider struct {
	commonRelayProviderBase

	transportInst *http.Transport
	clientInst    *http.Client

	ctx context.Context

	targetServerBaseURL string
	httpHostOverride    string
	exchangeMode        HTTPClientAccessExchangeMode
}

func NewHTTPClientAccessProvider(ctx context.Context, sharedSecretText string, messageBufferCount int,
	targetServerURL *url.URL, httpHostOverride string,
	channelIndex int, exchangeMode HTTPClientAccessExchangeMode,
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
	if err = p.initCommonRelayProviderBase(sharedSecretText, messageBufferCount); nil != err {
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
	collectTimeout := slowEmptyRawMessageCollectTimeout
	var failureCount int
	for {
		var exportedMessageCount, dispatchedMessageCount int
		var err error
		switch p.exchangeMode {
		case HTTPClientAccessBinaryMode:
			exportedMessageCount, dispatchedMessageCount, err = p.exchangeInBinary(collectTimeout)
		case HTTPClientAccessTextMode:
			exportedMessageCount, dispatchedMessageCount, err = p.exchangeInText(collectTimeout)
		default:
			err = fmt.Errorf("unknown exchange mode: %v", p.exchangeMode)
		}
		// log.Printf("TRACE: (HTTPClientAccessProvider::exchangeLoop) exported=%d, dispatched=%d; err=%v.", exportedMessageCount, dispatchedMessageCount, err)
		if nil != err {
			log.Printf("ERROR: (HTTPClientAccessProvider::ExchangeLoop) exchange failed: %v", err)
			failureCount++
		} else {
			failureCount = 0
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
			collectTimeout = slowEmptyRawMessageCollectTimeout
			continue
		}
		if (exportedMessageCount > 0) || (dispatchedMessageCount > 0) {
			collectTimeout = fastEmptyRawMessageCollectTimeout
		} else {
			collectTimeout = slowEmptyRawMessageCollectTimeout
		}
	}
}

func (p *HTTPClientAccessProvider) Start(waitGroup *sync.WaitGroup) {
	waitGroup.Add(1)
	go p.exchangeLoop(waitGroup)
}

// ReceiveMessage implement ServiceProvider interface.
func (p *HTTPClientAccessProvider) ReceiveMessage(rawMessage *RawMessage) (err error) {
	log.Printf("WARN: (HTTPClientAccessProvider::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	return
}

// SetMessageSender implement ServiceProvider interface.
func (p *HTTPClientAccessProvider) SetMessageSender(messageSender *MessageSender) {
	// TODO: implements
}

func (p *HTTPClientAccessProvider) EmitMessage(rawMessage *RawMessage) (err error) {
	return p.emitMessage(p.ctx, rawMessage)
}
