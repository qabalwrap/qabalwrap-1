package httpcontent

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type HTTPContentFetcher struct {
	qabalwrap.ServiceBase

	targetBaseURL    url.URL
	httpHostOverride string

	messageSender qabalwrap.MessageSender

	ctx    context.Context
	cancel context.CancelFunc

	fetchSlotServiceInstIdent qabalwrap.ServiceInstanceIdentifier
	lckFetchSlots             sync.Mutex
	freeFetchSlotIndexes      []int
	fetchSlots                []*httpContentFetchSlot
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

func (hnd *HTTPContentFetcher) allocateFetchSlot(ctx context.Context, spanEmitter *qabalwrap.TraceEmitter, srcSerialIdent int, requestIdent int32) (fetchSlot *httpContentFetchSlot) {
	spanEmitter = spanEmitter.StartSpan(hnd.ServiceInstanceIdent, "http-content-fetch-alloc-slot", "src=%d, req=%d", srcSerialIdent, requestIdent)
	hnd.lckFetchSlots.Lock()
	defer hnd.lckFetchSlots.Unlock()
	l := len(hnd.freeFetchSlotIndexes)
	if l == 0 {
		spanEmitter.FinishSpanFailed("out of free slot")
		return
	}
	targetIndex := hnd.freeFetchSlotIndexes[l-1]
	hnd.freeFetchSlotIndexes = hnd.freeFetchSlotIndexes[:(l - 1)]
	fetchSlot = newHTTPContentFetchSlot(ctx, hnd, targetIndex, hnd.messageSender, srcSerialIdent, requestIdent)
	hnd.fetchSlots[targetIndex] = fetchSlot
	spanEmitter.FinishSpanSuccess("slot-index=%d", targetIndex)
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

func (hnd *HTTPContentFetcher) getFetchSlot(spanEmitter *qabalwrap.TraceEmitter, fetchSlotIdent int32) (fetchSlot *httpContentFetchSlot) {
	spanEmitter = spanEmitter.StartSpan(hnd.ServiceInstanceIdent, "get-transfer-slot", "slot-ident=%d", fetchSlotIdent)
	hnd.lckFetchSlots.Lock()
	defer hnd.lckFetchSlots.Unlock()
	idx := int(fetchSlotIdent & 0x0000FFFF)
	if (idx < 0) || (idx >= len(hnd.fetchSlots)) {
		spanEmitter.FinishSpanFailedLogf("(HTTPContentFetcher::getFetchSlot) index out of range: %d, %d", fetchSlotIdent, idx)
		return
	}
	if (hnd.fetchSlots[idx] == nil) || (hnd.fetchSlots[idx].slotIdent != fetchSlotIdent) {
		spanEmitter.FinishSpanFailedLogf("(HTTPContentFetcher::getFetchSlot) identifier not match: %d, %d", fetchSlotIdent, idx)
		return
	}
	fetchSlot = hnd.fetchSlots[idx]
	spanEmitter.FinishSpanSuccessWithoutMessage()
	return
}

// ServeHTTP offer short cut for local fetch and serve.
func (hnd *HTTPContentFetcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: impl
}

// Setup prepare provider for operation.
// Should only invoke at maintenance thread in setup stage.
func (hnd *HTTPContentFetcher) Setup(
	serviceInstIdent qabalwrap.ServiceInstanceIdentifier,
	diagnosisEmitter *qabalwrap.DiagnosisEmitter,
	certProvider qabalwrap.CertificateProvider) (err error) {
	hnd.ServiceInstanceIdent = serviceInstIdent
	hnd.fetchSlotServiceInstIdent = serviceInstIdent + "-slot-f"
	return
}

func (hnd *HTTPContentFetcher) processContentRequest(spanEmitter *qabalwrap.TraceEmitter, srcSerialIdent int, m *qbw1grpcgen.HTTPContentRequest) {
	spanEmitter = spanEmitter.StartSpan(hnd.ServiceInstanceIdent, "http-content-fetch-process-req", "response-ident=%d", m.ResponseIdent)
	if m.ResponseIdent != 0 {
		if fetchSlot := hnd.getFetchSlot(spanEmitter, m.ResponseIdent); fetchSlot != nil {
			fetchSlot.reqCh <- m
			spanEmitter.FinishSpanSuccess("existed slot")
		} else {
			resp := qbw1grpcgen.HTTPContentResponse{
				RequestIdent:    m.RequestIdent,
				ResultStateCode: http.StatusServiceUnavailable,
				ContentBody:     []byte("fetch slot released"),
				IsComplete:      true,
			}
			hnd.messageSender.Send(spanEmitter, srcSerialIdent, qabalwrap.MessageContentHTTPContentResponse, &resp)
			spanEmitter.FinishSpanFailed("slot released")
		}
		return
	}
	fetchSlot := hnd.allocateFetchSlot(hnd.ctx, spanEmitter, srcSerialIdent, m.RequestIdent)
	if fetchSlot == nil {
		resp := qbw1grpcgen.HTTPContentResponse{
			RequestIdent:    m.RequestIdent,
			ResultStateCode: http.StatusServiceUnavailable,
			ContentBody:     []byte("fetch slot unavailable"),
			IsComplete:      true,
		}
		hnd.messageSender.Send(spanEmitter, srcSerialIdent, qabalwrap.MessageContentHTTPContentResponse, &resp)
		spanEmitter.FinishSpanFailed("slot unavailable")
		return
	}
	go fetchSlot.run(spanEmitter, m)
	spanEmitter.FinishSpanSuccess("new slot")
}

func (hnd *HTTPContentFetcher) processLinkClosed(spanEmitter *qabalwrap.TraceEmitter, m *qbw1grpcgen.HTTPContentLinkClosed) {
	spanEmitter = spanEmitter.StartSpan(hnd.ServiceInstanceIdent, "http-content-fetch-link-closed", "response-ident=%d", m.ResponseIdent)
	if m.ResponseIdent == 0 {
		spanEmitter.FinishSpanFailed("empty response identifier")
		return
	}
	if fetchSlot := hnd.getFetchSlot(spanEmitter, m.ResponseIdent); fetchSlot != nil {
		fetchSlot.cancel()
		spanEmitter.FinishSpanSuccess("cancelled closed link: response-ident=%d.", m.ResponseIdent)
	} else {
		spanEmitter.FinishSpanFailed("closed link not existed anymore: response-ident=%d.", m.ResponseIdent)
	}
}

// ReceiveMessage implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) ReceiveMessage(spanEmitter *qabalwrap.TraceEmitter, envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(hnd.ServiceInstanceIdent, "http-content-fetch-recv-msg")
	switch envelopedMessage.MessageContentType() {
	case qabalwrap.MessageContentHTTPContentRequest:
		var req qbw1grpcgen.HTTPContentRequest
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			spanEmitter.FinishSpanFailedLogf("(HTTPContentFetcher::ReceiveMessage::ContentRequest) unmarshal request failed: %v", err)
			return
		}
		hnd.processContentRequest(spanEmitter, envelopedMessage.SourceServiceIdent, &req)
		spanEmitter.FinishSpanSuccess("content request")
	case qabalwrap.MessageContentHTTPContentLinkClosed:
		var req qbw1grpcgen.HTTPContentLinkClosed
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			spanEmitter.FinishSpanFailedLogf("(HTTPContentFetcher::ReceiveMessage::LinkClosed) unmarshal request failed: %v", err)
			return
		}
		hnd.processLinkClosed(spanEmitter, &req)
		spanEmitter.FinishSpanSuccess("link close")
	default:
		spanEmitter.FinishSpanFailedLogf("(HTTPContentFetcher::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	}
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) SetMessageSender(messageSender qabalwrap.MessageSender) {
	hnd.messageSender = messageSender
}
