package qabalwrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

const (
	transferSlotResponseBufferSize = 8
	transferSlotRequestBufferSize  = 8
)

const (
	httpContentRequestMethodWebSocket = "WebSocket"
)

var websocketDefaultDialer = &websocket.Dialer{
	Proxy:            http.ProxyFromEnvironment,
	HandshakeTimeout: 45 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

var httpDefaultClient *http.Client

func init() {
	transportInst := http.DefaultTransport.(*http.Transport).Clone()
	transportInst.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	httpDefaultClient = &http.Client{
		Transport: transportInst,
	}
}

func checkHeaderToken(h http.Header, targetKey, targetToken string) bool {
	values := h.Values(targetKey)
	targetLen := len(targetToken)
	for _, v := range values {
		buf := make([]byte, 0, 16)
		l := len(v)
		for idx := 0; idx < l; idx++ {
			ch := v[idx]
			if ch > 127 {
				buf = buf[:0]
				continue
			}
			var b [2]uint64
			ch64 := uint64(ch)
			b[((ch64 >> 6) & 0x1)] = ch64 & 63
			if ((b[0] & 0x3FFA00000000000) != 0) || ((b[1] & 0x7FFFFFE00000000) != 0) {
				buf = append(buf, ch)
			} else if (b[1] & 0x07FFFFFE) != 0 {
				buf = append(buf, ch-'A'+'a')
			} else if (len(buf) == targetLen) && (string(buf) == targetToken) {
				return true
			} else {
				buf = buf[:0]
			}
		}
		if (len(buf) == targetLen) && (string(buf) == targetToken) {
			return true
		}
	}
	return false
}

func readBytesChunk(fullBuf []byte, bodyReader io.ReadCloser) (loadedBuf []byte, completed bool, err error) {
	loadedBuf = fullBuf
	var n int
	if n, err = bodyReader.Read(loadedBuf); nil != err {
		if err == io.EOF {
			completed = true
			if n <= 0 {
				loadedBuf = nil
			} else {
				loadedBuf = loadedBuf[:n]
			}
			err = nil
		} else {
			log.Printf("ERROR: (readBytesChunk) load request failed: %v", err)
		}
	} else if n > 0 {
		loadedBuf = loadedBuf[:n]
	} else {
		loadedBuf = nil
	}
	return
}

type httpContentTransferSlot struct {
	ctx       context.Context
	slotIndex int
	slotIdent int32
	respCh    chan *qbw1grpcgen.HTTPContentResponse

	messageSender     *MessageSender
	fetcherSeriaIdent int

	responseIdent int32
}

func newHTTPContentTransferSlot(ctx context.Context, slotIndex int, messageSender *MessageSender, fetcherSeriaIdent int) (s *httpContentTransferSlot) {
	var buf [2]byte
	io.ReadFull(rand.Reader, buf[:])
	slotIdent := int32(((uint32(binary.LittleEndian.Uint16(buf[:])) << 16) & 0x7FFF0000) | 0x00080000 | (uint32(slotIndex) & 0xFFFF))
	s = &httpContentTransferSlot{
		ctx:               ctx,
		slotIndex:         slotIndex,
		slotIdent:         slotIdent,
		respCh:            make(chan *qbw1grpcgen.HTTPContentResponse, transferSlotResponseBufferSize),
		messageSender:     messageSender,
		fetcherSeriaIdent: fetcherSeriaIdent,
	}
	return
}

func (slot *httpContentTransferSlot) sendToPeer(req *qbw1grpcgen.HTTPContentRequest) {
	slot.messageSender.Send(slot.fetcherSeriaIdent, MessageContentHTTPContentRequest, req)
}

func (slot *httpContentTransferSlot) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	req0 := qbw1grpcgen.HTTPContentRequest{
		RequestIdent:  slot.slotIdent,
		UrlPath:       r.URL.Path,
		UrlQuery:      r.URL.RawQuery,
		RequestMethod: httpContentRequestMethodWebSocket,
		Headers:       qbw1grpcgen.NewKeyValuesFromHTTPHeader(r.Header),
		IsComplete:    true,
	}
	slot.sendToPeer(&req0)
	// TODO: impl
}

func (slot *httpContentTransferSlot) serveRegular(w http.ResponseWriter, r *http.Request) {
	reqContentFullBuf := make([]byte, 1024)
	reqContentBuf, reqCompleted, err := readBytesChunk(reqContentFullBuf, r.Body)
	if nil != err {
		http.Error(w, "cannot load request", http.StatusBadRequest)
		return
	}
	req0 := &qbw1grpcgen.HTTPContentRequest{
		RequestIdent:  slot.slotIdent,
		UrlPath:       r.URL.Path,
		UrlQuery:      r.URL.RawQuery,
		RequestMethod: r.Method,
		RequestHost:   r.Host,
		Headers:       qbw1grpcgen.NewKeyValuesFromHTTPHeader(r.Header),
		ContentBody:   reqContentBuf,
		IsComplete:    reqCompleted,
	}
	slot.sendToPeer(req0)
	log.Printf("TRACE: (serveRegular) emit request [%s / %s]", r.Host, r.URL.Path)
	select {
	case resp := <-slot.respCh:
		if resp == nil {
			http.Error(w, "timeout", http.StatusBadGateway)
			log.Print("ERROR: (serveRegular) cannot have request response.")
			return
		}
		slot.responseIdent = resp.ResponseIdent
		if resp.IsComplete {
			if resp.ResultStateCode != 0 {
				w.WriteHeader(int(resp.ResultStateCode))
			} else {
				http.Error(w, "complete without result code.", http.StatusBadGateway)
			}
			if len(resp.ContentBody) > 0 {
				w.Write(resp.ContentBody)
			}
			return
		}
	case <-slot.ctx.Done():
		http.Error(w, "interrupted", http.StatusBadGateway)
		return
	}
	for !reqCompleted {
		if reqContentBuf, reqCompleted, err = readBytesChunk(reqContentFullBuf, r.Body); nil != err {
			log.Printf("ERROR: (HTTPContentServeHandler) load request failed (remaining parts): %v", err)
			reqCompleted = true
		}
		req0 = &qbw1grpcgen.HTTPContentRequest{
			RequestIdent:  slot.slotIdent,
			ResponseIdent: slot.responseIdent,
			ContentBody:   reqContentBuf,
			IsComplete:    reqCompleted,
		}
		slot.sendToPeer(req0)
	}
	emitedHeader := false
	for {
		select {
		case resp := <-slot.respCh:
			if resp == nil {
				if !emitedHeader {
					http.Error(w, "timeout", http.StatusBadGateway)
				}
				log.Print("ERROR: (serveRegular) cannot have request response.")
				return
			}
			if (!emitedHeader) && (resp.ResultStateCode != 0) {
				for _, kv := range resp.Headers {
					for _, vv := range kv.Values {
						w.Header().Add(kv.Key, vv)
					}
				}
				w.WriteHeader(int(resp.ResultStateCode))
				emitedHeader = true
			}
			if len(resp.ContentBody) > 0 {
				w.Write(resp.ContentBody)
			}
			if resp.IsComplete {
				return
			}
		case <-slot.ctx.Done():
			if !emitedHeader {
				http.Error(w, "interrupted", http.StatusBadGateway)
			}
			return
		}
	}
}

func (slot *httpContentTransferSlot) serve(w http.ResponseWriter, r *http.Request) {
	if checkHeaderToken(r.Header, "Connection", "upgrade") && checkHeaderToken(r.Header, "Upgrade", "websocket") {
		log.Printf("INFO: having websocket request at [%s]", r.URL.Path)
		slot.serveWebSocket(w, r)
		return
	}
	slot.serveRegular(w, r)
}

func (slot *httpContentTransferSlot) release() {
	close(slot.respCh)
}

type HTTPContentServeHandler struct {
	lckFetcherRef     sync.Mutex
	fetcherIdent      string
	fetcherSeriaIdent int

	messageSender *MessageSender

	lckTransferSlots        sync.Mutex
	freeTransferSlotIndexes []int
	transferSlots           []*httpContentTransferSlot
}

func NewHTTPContentServeHandler(fetcherIdent string, maxContentTransferSessions int) (hnd *HTTPContentServeHandler) {
	freeTransferSlotIndexes := make([]int, maxContentTransferSessions)
	transferSlots := make([]*httpContentTransferSlot, maxContentTransferSessions)
	for idx := 0; idx < maxContentTransferSessions; idx++ {
		freeTransferSlotIndexes[idx] = idx
	}
	return &HTTPContentServeHandler{
		fetcherIdent:            fetcherIdent,
		fetcherSeriaIdent:       UnknownServiceIdent,
		freeTransferSlotIndexes: freeTransferSlotIndexes,
		transferSlots:           transferSlots,
	}
}

func (hnd *HTTPContentServeHandler) allocateTransferSlot(ctx context.Context) (transferSlot *httpContentTransferSlot) {
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	l := len(hnd.freeTransferSlotIndexes)
	if l == 0 {
		return
	}
	targetIndex := hnd.freeTransferSlotIndexes[l-1]
	hnd.freeTransferSlotIndexes = hnd.freeTransferSlotIndexes[:(l - 1)]
	transferSlot = newHTTPContentTransferSlot(ctx, targetIndex, hnd.messageSender, hnd.fetcherSeriaIdent)
	hnd.transferSlots[targetIndex] = transferSlot
	return
}

func (hnd *HTTPContentServeHandler) releaseTransferSlot(transferSlot *httpContentTransferSlot) {
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	targetIndex := transferSlot.slotIndex
	if (hnd.transferSlots[targetIndex] == nil) || (hnd.transferSlots[targetIndex].slotIdent != transferSlot.slotIdent) {
		log.Printf("WARN: (HTTPContentServeHandler::releaseTransferSlot) attempt to release non-matched slot: %d", transferSlot.slotIdent)
		return
	}
	hnd.transferSlots[targetIndex].release()
	hnd.transferSlots[targetIndex] = nil
	hnd.freeTransferSlotIndexes = append(hnd.freeTransferSlotIndexes, targetIndex)
}

func (hnd *HTTPContentServeHandler) getTransferSlot(transferSlotIdent int32) (transferSlot *httpContentTransferSlot) {
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	idx := int(transferSlotIdent & 0x0000FFFF)
	if (idx < 0) || (idx >= len(hnd.transferSlots)) {
		log.Printf("WARN: (HTTPContentServeHandler::getTransferSlot) index out of range: %d, %d", transferSlotIdent, idx)
		return
	}
	if (hnd.transferSlots[idx] == nil) || (hnd.transferSlots[idx].slotIdent != transferSlotIdent) {
		log.Printf("WARN: (HTTPContentServeHandler::getTransferSlot) identifier not match: %d, %d", transferSlotIdent, idx)
		return
	}
	transferSlot = hnd.transferSlots[idx]
	return
}

func (hnd *HTTPContentServeHandler) isFetcherLinkAvailable() bool {
	if hnd.messageSender == nil {
		return false
	}
	hnd.lckFetcherRef.Lock()
	defer hnd.lckFetcherRef.Unlock()
	if hnd.fetcherSeriaIdent != UnknownServiceIdent {
		return true
	}
	serviceRef := hnd.messageSender.GetServiceByTextIdent(hnd.fetcherIdent)
	if serviceRef == nil {
		log.Printf("ERROR: (HTTPContentServeHandler::isFetcherLinkAvailable) service reference unavailable [%s]", hnd.fetcherIdent)
		return false
	}
	if !serviceRef.HasReceiver() {
		log.Printf("ERROR: (HTTPContentServeHandler::isFetcherLinkAvailable) fetcher receiver unavailable [%s]", hnd.fetcherIdent)
		return false
	}
	hnd.fetcherSeriaIdent = serviceRef.SerialIdent
	return true
}

func (hnd *HTTPContentServeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !hnd.isFetcherLinkAvailable() {
		http.Error(w, "content link unavailable", http.StatusServiceUnavailable)
		return
	}
	transferSlot := hnd.allocateTransferSlot(ctx)
	if transferSlot == nil {
		http.Error(w, "out of transfer slots", http.StatusServiceUnavailable)
		return
	}
	defer hnd.releaseTransferSlot(transferSlot)
	transferSlot.serve(w, r)
}

func (hnd *HTTPContentServeHandler) processContentResponse(m *qbw1grpcgen.HTTPContentResponse) {
	if m.RequestIdent == 0 {
		log.Printf("WARN: (HTTPContentFetcher::processContentResponse) empty request identifier: response-ident=%d", m.ResponseIdent)
		return
	}
	transferSlot := hnd.getTransferSlot(m.RequestIdent)
	if transferSlot == nil {
		log.Printf("WARN: (HTTPContentFetcher::processContentResponse) transfer slot is gone: request-ident=%d, response-ident=%d", m.RequestIdent, m.ResponseIdent)
		return
	}
	transferSlot.respCh <- m
}

// ReceiveMessage implement ServiceProvider interface.
func (hnd *HTTPContentServeHandler) ReceiveMessage(rawMessage *RawMessage) (err error) {
	switch rawMessage.MessageContentType() {
	case MessageContentHTTPContentResponse:
		var req qbw1grpcgen.HTTPContentResponse
		if err = rawMessage.Unmarshal(&req); nil != err {
			return
		}
		hnd.processContentResponse(&req)
	}
	log.Printf("WARN: (HTTPContentServeHandler::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentServeHandler) SetMessageSender(messageSender *MessageSender) {
	hnd.messageSender = messageSender
}

func (hnd *HTTPContentServeHandler) Stop() {
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	for idx, slot := range hnd.transferSlots {
		if slot == nil {
			continue
		}
		log.Printf("INFO: releasing slot due to stop: %d", idx)
		hnd.releaseTransferSlot(slot)
	}
}

type httpContentFetchSlot struct {
	ctx             context.Context
	upstreamFetcher *HTTPContentFetcher
	slotIndex       int
	slotIdent       int32
	reqCh           chan *qbw1grpcgen.HTTPContentRequest
	msgSender       *MessageSender
	peerSerialIdent int
	requestIdent    int32
}

func newHTTPContentFetchSlot(ctx context.Context, upstreamFetcher *HTTPContentFetcher, slotIndex int, msgSender *MessageSender, srcSerialIdent int, requestIdent int32) (s *httpContentFetchSlot) {
	var buf [2]byte
	io.ReadFull(rand.Reader, buf[:])
	slotIdent := int32(((uint32(binary.LittleEndian.Uint16(buf[:])) << 16) & 0x7FFF0000) | 0x00010000 | (uint32(slotIndex) & 0xFFFF))
	s = &httpContentFetchSlot{
		ctx:             ctx,
		upstreamFetcher: upstreamFetcher,
		slotIndex:       slotIndex,
		slotIdent:       slotIdent,
		reqCh:           make(chan *qbw1grpcgen.HTTPContentRequest, transferSlotRequestBufferSize),
		msgSender:       msgSender,
		peerSerialIdent: srcSerialIdent,
		requestIdent:    requestIdent,
	}
	return
}

func (slot *httpContentFetchSlot) sendToPeer(resp *qbw1grpcgen.HTTPContentResponse) {
	slot.msgSender.Send(slot.peerSerialIdent, MessageContentHTTPContentResponse, resp)
}

func (slot *httpContentFetchSlot) errorToPeer(err error) {
	slot.sendToPeer(&qbw1grpcgen.HTTPContentResponse{
		ResponseIdent:   slot.slotIdent,
		RequestIdent:    slot.requestIdent,
		ResultStateCode: http.StatusInternalServerError,
		ContentBody:     []byte(err.Error()),
		IsComplete:      true,
	})
}

func (slot *httpContentFetchSlot) runWebSocket(targetURL *url.URL, h http.Header) {

}

func (slot *httpContentFetchSlot) run(req *qbw1grpcgen.HTTPContentRequest) {
	defer slot.close()
	targetURL := slot.upstreamFetcher.targetBaseURL
	targetURL.Path = req.UrlPath
	targetURL.RawQuery = req.UrlQuery
	if req.RequestMethod == httpContentRequestMethodWebSocket {
		slot.runWebSocket(&targetURL, req.GetHeadersHTTPHeader())
		return
	}
	var httpReq *http.Request
	var err error
	if req.IsComplete {
		if len(req.ContentBody) > 0 {
			httpReq, err = http.NewRequestWithContext(slot.ctx, req.RequestMethod, targetURL.String(), bytes.NewReader(req.ContentBody))
		} else {
			httpReq, err = http.NewRequestWithContext(slot.ctx, req.RequestMethod, targetURL.String(), nil)
		}
	} else {
		reqBodyReader, reqBodyWriter := io.Pipe()
		httpReq, err = http.NewRequestWithContext(slot.ctx, req.RequestMethod, targetURL.String(), reqBodyReader)
		go func() {
			for {
				req1 := <-slot.reqCh
				if req1 == nil {
					break
				}
				if len(req1.ContentBody) > 0 {
					reqBodyWriter.Write(req1.ContentBody)
				}
				if req1.IsComplete {
					break
				}
			}
			reqBodyWriter.Close()
		}()
	}
	if nil != err {
		log.Printf("ERROR: (httpContentFetchSlot::run) cannot construct request: %v", err)
		slot.errorToPeer(err)
		return
	}
	slot.sendToPeer(
		&qbw1grpcgen.HTTPContentResponse{
			ResponseIdent: slot.slotIdent,
			RequestIdent:  slot.requestIdent,
		})
	if slot.upstreamFetcher.httpHostOverride != "" {
		httpReq.Host = slot.upstreamFetcher.httpHostOverride
	} else if req.RequestHost != "" {
		httpReq.Host = req.RequestHost
	}
	httpReq.Header = req.GetHeadersHTTPHeader()
	resp, err := httpDefaultClient.Do(httpReq)
	if nil != err {
		log.Printf("ERROR: (httpContentFetchSlot::run) cannot issue request: %v", err)
		slot.errorToPeer(err)
		return
	}
	defer resp.Body.Close()
	respContentFullBuf := make([]byte, 1024)
	respContentBuf, respCompleted, err := readBytesChunk(respContentFullBuf, resp.Body)
	if nil != err {
		slot.errorToPeer(err)
		return
	}
	slot.sendToPeer(
		&qbw1grpcgen.HTTPContentResponse{
			ResponseIdent:   slot.slotIdent,
			RequestIdent:    slot.requestIdent,
			ResultStateCode: int32(resp.StatusCode),
			Headers:         qbw1grpcgen.NewKeyValuesFromHTTPHeader(resp.Header),
			ContentBody:     respContentBuf,
			IsComplete:      respCompleted,
		})
	for !respCompleted {
		if respContentBuf, respCompleted, err = readBytesChunk(respContentFullBuf, resp.Body); nil != err {
			log.Printf("ERROR: (httpContentFetchSlot::run) failed on loading respponse: %v", err)
			respCompleted = true
		}
		slot.sendToPeer(
			&qbw1grpcgen.HTTPContentResponse{
				ResponseIdent: slot.slotIdent,
				RequestIdent:  slot.requestIdent,
				ContentBody:   respContentBuf,
				IsComplete:    respCompleted,
			})
	}
}

func (slot *httpContentFetchSlot) release() {
	close(slot.reqCh)
}

func (slot *httpContentFetchSlot) close() {
	slot.upstreamFetcher.releaseFetchSlot(slot)
}

type HTTPContentFetcher struct {
	targetBaseURL    url.URL
	httpHostOverride string

	messageSender *MessageSender

	ctx    context.Context
	cancel context.CancelFunc

	lckFetchSlots        sync.Mutex
	freeFetchSlotIndexes []int
	fetchSlots           []*httpContentFetchSlot
}

func NewHTTPContentFetcher(targetBaseURL *url.URL, httpHostOverride string, maxContentFetchSessions int) (f *HTTPContentFetcher) {
	freeFetchSlotIndexes := make([]int, maxContentFetchSessions)
	fetchSlots := make([]*httpContentFetchSlot, maxContentFetchSessions)
	for idx := 0; idx < maxContentFetchSessions; idx++ {
		freeFetchSlotIndexes[idx] = idx
	}
	ctx, cancel := context.WithCancel(context.Background())
	f = &HTTPContentFetcher{
		targetBaseURL:        *targetBaseURL,
		httpHostOverride:     httpHostOverride,
		ctx:                  ctx,
		cancel:               cancel,
		freeFetchSlotIndexes: freeFetchSlotIndexes,
		fetchSlots:           fetchSlots,
	}
	return
}

func (hnd *HTTPContentFetcher) allocateFetchSlot(ctx context.Context, srcSerialIdent int, requestIdent int32) (fetchSlot *httpContentFetchSlot) {
	hnd.lckFetchSlots.Lock()
	defer hnd.lckFetchSlots.Unlock()
	l := len(hnd.freeFetchSlotIndexes)
	if l == 0 {
		return
	}
	targetIndex := hnd.freeFetchSlotIndexes[l-1]
	hnd.freeFetchSlotIndexes = hnd.freeFetchSlotIndexes[:(l - 1)]
	fetchSlot = newHTTPContentFetchSlot(ctx, hnd, targetIndex, hnd.messageSender, srcSerialIdent, requestIdent)
	hnd.fetchSlots[targetIndex] = fetchSlot
	return
}

func (hnd *HTTPContentFetcher) releaseFetchSlot(fetchSlot *httpContentFetchSlot) {
	hnd.lckFetchSlots.Lock()
	defer hnd.lckFetchSlots.Unlock()
	targetIndex := fetchSlot.slotIndex
	if (hnd.fetchSlots[targetIndex] == nil) || (hnd.fetchSlots[targetIndex].slotIdent != fetchSlot.slotIdent) {
		log.Printf("WARN: (HTTPContentFetcher::releaseFetchSlot) attempt to release non-matched slot: %d", fetchSlot.slotIdent)
		return
	}
	hnd.fetchSlots[targetIndex].release()
	hnd.fetchSlots[targetIndex] = nil
	hnd.freeFetchSlotIndexes = append(hnd.freeFetchSlotIndexes, targetIndex)
}

func (hnd *HTTPContentFetcher) getFetchSlot(fetchSlotIdent int32) (fetchSlot *httpContentFetchSlot) {
	hnd.lckFetchSlots.Lock()
	defer hnd.lckFetchSlots.Unlock()
	idx := int(fetchSlotIdent & 0x0000FFFF)
	if (idx < 0) || (idx >= len(hnd.fetchSlots)) {
		log.Printf("WARN: (HTTPContentFetcher::getFetchSlot) index out of range: %d, %d", fetchSlotIdent, idx)
		return
	}
	if (hnd.fetchSlots[idx] == nil) || (hnd.fetchSlots[idx].slotIdent != fetchSlotIdent) {
		log.Printf("WARN: (HTTPContentFetcher::getFetchSlot) identifier not match: %d, %d", fetchSlotIdent, idx)
		return
	}
	fetchSlot = hnd.fetchSlots[idx]
	return
}

// ServeHTTP offer short cut for local fetch and serve.
func (hnd *HTTPContentFetcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: impl
}

func (hnd *HTTPContentFetcher) processContentRequest(srcSerialIdent int, m *qbw1grpcgen.HTTPContentRequest) {
	if m.ResponseIdent != 0 {
		fetchSlot := hnd.getFetchSlot(m.ResponseIdent)
		fetchSlot.reqCh <- m
		return
	}
	fetchSlot := hnd.allocateFetchSlot(hnd.ctx, srcSerialIdent, m.RequestIdent)
	if fetchSlot == nil {
		resp := qbw1grpcgen.HTTPContentResponse{
			RequestIdent:    m.RequestIdent,
			ResultStateCode: http.StatusServiceUnavailable,
			ContentBody:     []byte("fetch slot unavailable"),
			IsComplete:      true,
		}
		hnd.messageSender.Send(srcSerialIdent, MessageContentHTTPContentResponse, &resp)
		return
	}
	go fetchSlot.run(m)
}

// ReceiveMessage implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) ReceiveMessage(rawMessage *RawMessage) (err error) {
	switch rawMessage.MessageContentType() {
	case MessageContentHTTPContentRequest:
		var req qbw1grpcgen.HTTPContentRequest
		if err = rawMessage.Unmarshal(&req); nil != err {
			return
		}
		hnd.processContentRequest(rawMessage.SourceServiceIdent, &req)
	}
	log.Printf("WARN: (HTTPContentFetcher::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", rawMessage.SourceServiceIdent, rawMessage.DestinationServiceIdent, rawMessage.MessageContentType())
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) SetMessageSender(messageSender *MessageSender) {
	hnd.messageSender = messageSender
}
