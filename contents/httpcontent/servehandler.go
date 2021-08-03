package httpcontent

import (
	"context"
	"log"
	"net/http"
	"sync"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type HTTPContentServeHandler struct {
	qabalwrap.ServiceBase

	lckFetcherRef     sync.Mutex
	fetcherIdent      string
	fetcherSeriaIdent int

	messageSender qabalwrap.MessageSender

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
		fetcherSeriaIdent:       qabalwrap.UnknownServiceIdent,
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
	if hnd.transferSlots[idx] == nil {
		log.Printf("WARN: (HTTPContentServeHandler::getTransferSlot) identifier not existed: ident=%d, idx=%d", transferSlotIdent, idx)
		return
	} else if hnd.transferSlots[idx].slotIdent != transferSlotIdent {
		log.Printf("WARN: (HTTPContentServeHandler::getTransferSlot) identifier not match: ident=%d, idx=%d", transferSlotIdent, idx)
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
	if hnd.fetcherSeriaIdent != qabalwrap.UnknownServiceIdent {
		return true
	}
	serialIdent, hasReceiver, ok := hnd.messageSender.ServiceSerialIdentByTextIdent(hnd.fetcherIdent)
	if !ok {
		log.Printf("ERROR: (HTTPContentServeHandler::isFetcherLinkAvailable) service reference unavailable [%s]", hnd.fetcherIdent)
		return false
	}
	if !hasReceiver {
		log.Printf("ERROR: (HTTPContentServeHandler::isFetcherLinkAvailable) fetcher receiver unavailable [%s]", hnd.fetcherIdent)
		return false
	}
	hnd.fetcherSeriaIdent = serialIdent
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
func (hnd *HTTPContentServeHandler) ReceiveMessage(envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	switch envelopedMessage.MessageContentType() {
	case qabalwrap.MessageContentHTTPContentResponse:
		var req qbw1grpcgen.HTTPContentResponse
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			log.Printf("ERROR: (HTTPContentServeHandler::ReceiveMessage) unmarshal response failed: %v", err)
			return
		}
		hnd.processContentResponse(&req)
	default:
		log.Printf("WARN: (HTTPContentServeHandler::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	}
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentServeHandler) SetMessageSender(messageSender qabalwrap.MessageSender) {
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
