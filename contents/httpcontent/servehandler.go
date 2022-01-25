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

	diagnosisEmitter *qabalwrap.DiagnosisEmitter
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

func (hnd *HTTPContentServeHandler) allocateTransferSlot(ctx context.Context, spanEmitter *qabalwrap.TraceEmitter) (transferSlot *httpContentTransferSlot) {
	spanEmitter = spanEmitter.StartSpan("allocate-transfer-slot")
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	l := len(hnd.freeTransferSlotIndexes)
	if l == 0 {
		spanEmitter.FinishSpan("failed: no free slot available")
		return
	}
	targetIndex := hnd.freeTransferSlotIndexes[l-1]
	hnd.freeTransferSlotIndexes = hnd.freeTransferSlotIndexes[:(l - 1)]
	transferSlot = newHTTPContentTransferSlot(ctx, targetIndex, hnd.messageSender, hnd.fetcherSeriaIdent)
	hnd.transferSlots[targetIndex] = transferSlot
	spanEmitter.FinishSpan("success: found: %d", targetIndex)
	return
}

func (hnd *HTTPContentServeHandler) releaseTransferSlot(spanEmitter *qabalwrap.TraceEmitter, transferSlot *httpContentTransferSlot) {
	spanEmitter = spanEmitter.StartSpan("release-transfer-slot")
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	targetIndex := transferSlot.slotIndex
	if (hnd.transferSlots[targetIndex] == nil) || (hnd.transferSlots[targetIndex].slotIdent != transferSlot.slotIdent) {
		spanEmitter.FinishSpanLogError("failed: (HTTPContentServeHandler::releaseTransferSlot) attempt to release non-matched slot: %d", transferSlot.slotIdent)
		return
	}
	hnd.transferSlots[targetIndex].release()
	hnd.transferSlots[targetIndex] = nil
	hnd.freeTransferSlotIndexes = append(hnd.freeTransferSlotIndexes, targetIndex)
	spanEmitter.FinishSpan("success")
}

func (hnd *HTTPContentServeHandler) getTransferSlot(spanEmitter *qabalwrap.TraceEmitter, transferSlotIdent int32) (transferSlot *httpContentTransferSlot) {
	spanEmitter = spanEmitter.StartSpan("get-transfer-slot: slot-ident=%d", transferSlotIdent)
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	idx := int(transferSlotIdent & 0x0000FFFF)
	if (idx < 0) || (idx >= len(hnd.transferSlots)) {
		spanEmitter.FinishSpanLogError("failed: (HTTPContentServeHandler::getTransferSlot) index out of range: %d, %d", transferSlotIdent, idx)
		return
	}
	if hnd.transferSlots[idx] == nil {
		spanEmitter.FinishSpanLogError("failed: (HTTPContentServeHandler::getTransferSlot) identifier not existed: ident=%d, idx=%d", transferSlotIdent, idx)
		return
	} else if hnd.transferSlots[idx].slotIdent != transferSlotIdent {
		spanEmitter.FinishSpanLogError("failed: (HTTPContentServeHandler::getTransferSlot) identifier not match: ident=%d, idx=%d", transferSlotIdent, idx)
		return
	}
	transferSlot = hnd.transferSlots[idx]
	spanEmitter.FinishSpan("success")
	return
}

func (hnd *HTTPContentServeHandler) isFetcherLinkAvailable(spanEmitter *qabalwrap.TraceEmitter) bool {
	spanEmitter = spanEmitter.StartSpan("check-fetcher-link")
	if hnd.messageSender == nil {
		spanEmitter.FinishSpan("failed: empty message sender")
		return false
	}
	hnd.lckFetcherRef.Lock()
	defer hnd.lckFetcherRef.Unlock()
	if hnd.fetcherSeriaIdent != qabalwrap.UnknownServiceIdent {
		spanEmitter.FinishSpan("success: cached")
		return true
	}
	serialIdent, hasReceiver, ok := hnd.messageSender.ServiceSerialIdentByTextIdent(hnd.fetcherIdent)
	if !ok {
		spanEmitter.FinishSpan("failed: (HTTPContentServeHandler::isFetcherLinkAvailable) service reference unavailable [%s]",
			hnd.fetcherIdent)
		return false
	}
	if !hasReceiver {
		spanEmitter.FinishSpan("failed: (HTTPContentServeHandler::isFetcherLinkAvailable) fetcher receiver unavailable [%s]", hnd.fetcherIdent)
		return false
	}
	hnd.fetcherSeriaIdent = serialIdent
	spanEmitter.FinishSpan("success: fetcher serial identifier: %d", serialIdent)
	return true
}

func (hnd *HTTPContentServeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	traceEmitter := hnd.diagnosisEmitter.StartTrace("http-content-serve: [%s:%d] %s %s",
		hnd.fetcherIdent, hnd.fetcherSeriaIdent, r.Method, r.URL.String())
	if !hnd.isFetcherLinkAvailable(traceEmitter) {
		http.Error(w, "content link unavailable", http.StatusServiceUnavailable)
		traceEmitter.FinishTrace("failed: fetcher link unavailable")
		return
	}
	transferSlot := hnd.allocateTransferSlot(ctx, traceEmitter)
	if transferSlot == nil {
		http.Error(w, "out of transfer slots", http.StatusServiceUnavailable)
		traceEmitter.FinishTrace("failed: out of transfer slots")
		return
	}
	defer hnd.releaseTransferSlot(traceEmitter, transferSlot)
	transferSlot.serve(traceEmitter, w, r)
}

func (hnd *HTTPContentServeHandler) processContentResponse(
	spanEmitter *qabalwrap.TraceEmitter,
	m *qbw1grpcgen.HTTPContentResponse,
	sourceServiceIdent int) {
	if m.RequestIdent == 0 {
		spanEmitter.EventWarning("(HTTPContentFetcher::processContentResponse) empty request identifier: response-ident=%d", m.ResponseIdent)
		return
	}
	transferSlot := hnd.getTransferSlot(spanEmitter, m.RequestIdent)
	if transferSlot == nil {
		spanEmitter.EventWarning("(HTTPContentFetcher::processContentResponse) transfer slot is gone: request-ident=%d, response-ident=%d", m.RequestIdent, m.ResponseIdent)
		hnd.messageSender.Send(spanEmitter, sourceServiceIdent, qabalwrap.MessageContentHTTPContentLinkClosed, &qbw1grpcgen.HTTPContentLinkClosed{
			RequestIdent:  m.RequestIdent,
			ResponseIdent: m.ResponseIdent,
		})
		return
	}
	transferSlot.respCh <- &tracedHTTPContentResponse{
		spanEmitter:     spanEmitter,
		contentResponse: m,
	}
}

// Setup prepare provider for operation.
// Should only invoke at maintenance thread in setup stage.
func (hnd *HTTPContentServeHandler) Setup(diagnosisEmitter *qabalwrap.DiagnosisEmitter, certProvider qabalwrap.CertificateProvider) (err error) {
	hnd.diagnosisEmitter = diagnosisEmitter
	return
}

// ReceiveMessage implement ServiceProvider interface.
func (hnd *HTTPContentServeHandler) ReceiveMessage(spanEmitter *qabalwrap.TraceEmitter, envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan("http-content-serve-recv-msg")
	switch envelopedMessage.MessageContentType() {
	case qabalwrap.MessageContentHTTPContentResponse:
		var req qbw1grpcgen.HTTPContentResponse
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			spanEmitter.FinishSpanLogError("failed: (HTTPContentServeHandler::ReceiveMessage) unmarshal response failed: %v", err)
			return
		}
		hnd.processContentResponse(spanEmitter, &req, envelopedMessage.SourceServiceIdent)
		spanEmitter.FinishSpan("success")
	default:
		spanEmitter.FinishSpanLogError("failed: (HTTPContentServeHandler::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	}
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentServeHandler) SetMessageSender(messageSender qabalwrap.MessageSender) {
	hnd.messageSender = messageSender
}

func (hnd *HTTPContentServeHandler) Stop() {
	traceEmitter := hnd.diagnosisEmitter.StartTrace("stop-http-content-serve")
	defer traceEmitter.FinishTrace("success")
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	for idx, slot := range hnd.transferSlots {
		if slot == nil {
			continue
		}
		log.Printf("INFO: releasing slot due to stop: %d", idx)
		hnd.releaseTransferSlot(traceEmitter, slot)
	}
}
