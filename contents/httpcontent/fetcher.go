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

	messageSender *qabalwrap.MessageSender

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
		hnd.messageSender.Send(srcSerialIdent, qabalwrap.MessageContentHTTPContentResponse, &resp)
		return
	}
	go fetchSlot.run(m)
}

// ReceiveMessage implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) ReceiveMessage(envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	switch envelopedMessage.MessageContentType() {
	case qabalwrap.MessageContentHTTPContentRequest:
		var req qbw1grpcgen.HTTPContentRequest
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			return
		}
		hnd.processContentRequest(envelopedMessage.SourceServiceIdent, &req)
	}
	log.Printf("WARN: (HTTPContentFetcher::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentFetcher) SetMessageSender(messageSender *qabalwrap.MessageSender) {
	hnd.messageSender = messageSender
}
