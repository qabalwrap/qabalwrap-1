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

func (hnd *HTTPContentFetcher) allocateFetchSlot(ctx context.Context, spanEmitter *qabalwrap.TraceEmitter, srcSerialIdent int, requestIdent int32) (fetchSlot *httpContentFetchSlot) {
	spanEmitter = spanEmitter.StartSpan("http-content-fetch-alloc-slot: src=%d, req=%d", srcSerialIdent, requestIdent)
	hnd.lckFetchSlots.Lock()
	defer hnd.lckFetchSlots.Unlock()
	l := len(hnd.freeFetchSlotIndexes)
	if l == 0 {
		spanEmitter.FinishSpan("failed: out of free slot")
		return
	}
	targetIndex := hnd.freeFetchSlotIndexes[l-1]
	hnd.freeFetchSlotIndexes = hnd.freeFetchSlotIndexes[:(l - 1)]
	fetchSlot = newHTTPContentFetchSlot(ctx, hnd, targetIndex, hnd.messageSender, srcSerialIdent, requestIdent)
	hnd.fetchSlots[targetIndex] = fetchSlot
	spanEmitter.FinishSpan("success: slot-index=%d", targetIndex)
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
	spanEmitter = spanEmitter.StartSpan("get-transfer-slot: slot-ident=%d", fetchSlotIdent)
	hnd.lckFetchSlots.Lock()
	defer hnd.lckFetchSlots.Unlock()
	idx := int(fetchSlotIdent & 0x0000FFFF)
	if (idx < 0) || (idx >= len(hnd.fetchSlots)) {
		spanEmitter.FinishSpanErrorf("failed: (HTTPContentFetcher::getFetchSlot) index out of range: %d, %d", fetchSlotIdent, idx)
		return
	}
	if (hnd.fetchSlots[idx] == nil) || (hnd.fetchSlots[idx].slotIdent != fetchSlotIdent) {
		spanEmitter.FinishSpanErrorf("failed: (HTTPContentFetcher::getFetchSlot) identifier not match: %d, %d", fetchSlotIdent, idx)
		return
	}
	fetchSlot = hnd.fetchSlots[idx]
	spanEmitter.FinishSpan("success")
	return
}

// ServeHTTP offer short cut for local fetch and serve.
func (hnd *HTTPContentFetcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: impl
}

func (hnd *HTTPContentFetcher) processContentRequest(spanEmitter *qabalwrap.TraceEmitter, srcSerialIdent int, m *qbw1grpcgen.HTTPContentRequest) {
	spanEmitter = spanEmitter.StartSpan("http-content-fetch-process-req: %d", m.ResponseIdent)
	if m.ResponseIdent != 0 {
		if fetchSlot := hnd.getFetchSlot(spanEmitter, m.ResponseIdent); fetchSlot != nil {
			fetchSlot.reqCh <- m
			spanEmitter.FinishSpan("success: existed slot")
		} else {
			resp := qbw1grpcgen.HTTPContentResponse{
				RequestIdent:    m.RequestIdent,
				ResultStateCode: http.StatusServiceUnavailable,
				ContentBody:     []byte("fetch slot released"),
				IsComplete:      true,
			}
			hnd.messageSender.Send(spanEmitter, srcSerialIdent, qabalwrap.MessageContentHTTPContentResponse, &resp)
			spanEmitter.FinishSpan("failed: slot released")
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
		spanEmitter.FinishSpan("failed: slot unavailable")
		return
	}
	go fetchSlot.run(spanEmitter, m)
	spanEmitter.FinishSpan("success: new slot")
}

func (hnd *HTTPContentFetcher) processLinkClosed(spanEmitter *qabalwrap.TraceEmitter, m *qbw1grpcgen.HTTPContentLinkClosed) {
	spanEmitter = spanEmitter.StartSpan("http-content-fetch-link-closed: resp=%d", m.ResponseIdent)
	if m.ResponseIdent == 0 {
		spanEmitter.FinishSpan("failed: empty response identifier")
		return
	}
	if fetchSlot := hnd.getFetchSlot(spanEmitter, m.ResponseIdent); fetchSlot != nil {
		fetchSlot.cancel()
		spanEmitter.FinishSpan("success: cancelled closed link: response-ident=%d.", m.ResponseIdent)
	} else {
		spanEmitter.FinishSpan("failed: closed link not existed anymore: response-ident=%d.", m.ResponseIdent)
	}
}

// ReceiveMessage implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) ReceiveMessage(spanEmitter *qabalwrap.TraceEmitter, envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan("http-content-fetch-recv-msg")
	switch envelopedMessage.MessageContentType() {
	case qabalwrap.MessageContentHTTPContentRequest:
		var req qbw1grpcgen.HTTPContentRequest
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			spanEmitter.FinishSpanErrorf("failed: (HTTPContentFetcher::ReceiveMessage::ContentRequest) unmarshal request failed: %v", err)
			return
		}
		hnd.processContentRequest(spanEmitter, envelopedMessage.SourceServiceIdent, &req)
		spanEmitter.FinishSpan("success: content request")
	case qabalwrap.MessageContentHTTPContentLinkClosed:
		var req qbw1grpcgen.HTTPContentLinkClosed
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			spanEmitter.FinishSpanErrorf("failed: (HTTPContentFetcher::ReceiveMessage::LinkClosed) unmarshal request failed: %v", err)
			return
		}
		hnd.processLinkClosed(spanEmitter, &req)
		spanEmitter.FinishSpan("success: link close")
	default:
		spanEmitter.FinishSpanErrorf("failed: (HTTPContentFetcher::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	}
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) SetMessageSender(messageSender qabalwrap.MessageSender) {
	hnd.messageSender = messageSender
}
