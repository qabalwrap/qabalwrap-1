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

	transferSlotServiceInstIdent qabalwrap.ServiceInstanceIdentifier
	lckTransferSlots             sync.Mutex
	freeTransferSlotIndexes      []int
	transferSlots                []*httpContentTransferSlot

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
	spanEmitter = spanEmitter.StartSpanWithoutMessage(hnd.ServiceInstanceIdent, "allocate-transfer-slot")
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	l := len(hnd.freeTransferSlotIndexes)
	if l == 0 {
		spanEmitter.FinishSpanFailedLogf("no free slot available")
		return
	}
	targetIndex := hnd.freeTransferSlotIndexes[l-1]
	hnd.freeTransferSlotIndexes = hnd.freeTransferSlotIndexes[:(l - 1)]
	transferSlot = newHTTPContentTransferSlot(ctx, hnd.transferSlotServiceInstIdent, targetIndex, hnd.messageSender, hnd.fetcherSeriaIdent)
	hnd.transferSlots[targetIndex] = transferSlot
	spanEmitter.FinishSpanSuccess("found: %d", targetIndex)
	return
}

func (hnd *HTTPContentServeHandler) releaseTransferSlot(spanEmitter *qabalwrap.TraceEmitter, transferSlot *httpContentTransferSlot) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(hnd.ServiceInstanceIdent, "release-transfer-slot")
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	targetIndex := transferSlot.slotIndex
	if (hnd.transferSlots[targetIndex] == nil) || (hnd.transferSlots[targetIndex].slotIdent != transferSlot.slotIdent) {
		spanEmitter.FinishSpanFailedLogf("(HTTPContentServeHandler::releaseTransferSlot) attempt to release non-matched slot: %d", transferSlot.slotIdent)
		return
	}
	hnd.transferSlots[targetIndex].release()
	hnd.transferSlots[targetIndex] = nil
	hnd.freeTransferSlotIndexes = append(hnd.freeTransferSlotIndexes, targetIndex)
	spanEmitter.FinishSpanSuccessWithoutMessage()
}

func (hnd *HTTPContentServeHandler) getTransferSlot(spanEmitter *qabalwrap.TraceEmitter, transferSlotIdent int32) (transferSlot *httpContentTransferSlot) {
	spanEmitter = spanEmitter.StartSpan(hnd.ServiceInstanceIdent, "get-transfer-slot", "slot-ident=%d", transferSlotIdent)
	hnd.lckTransferSlots.Lock()
	defer hnd.lckTransferSlots.Unlock()
	idx := int(transferSlotIdent & 0x0000FFFF)
	if (idx < 0) || (idx >= len(hnd.transferSlots)) {
		spanEmitter.FinishSpanFailedLogf("(HTTPContentServeHandler::getTransferSlot) index out of range: %d, %d", transferSlotIdent, idx)
		return
	}
	if hnd.transferSlots[idx] == nil {
		spanEmitter.FinishSpanFailedLogf("(HTTPContentServeHandler::getTransferSlot) identifier not existed: ident=%d, idx=%d", transferSlotIdent, idx)
		return
	} else if hnd.transferSlots[idx].slotIdent != transferSlotIdent {
		spanEmitter.FinishSpanFailedLogf("(HTTPContentServeHandler::getTransferSlot) identifier not match: ident=%d, idx=%d", transferSlotIdent, idx)
		return
	}
	transferSlot = hnd.transferSlots[idx]
	spanEmitter.FinishSpanSuccessWithoutMessage()
	return
}

func (hnd *HTTPContentServeHandler) isFetcherLinkAvailable(spanEmitter *qabalwrap.TraceEmitter) bool {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(hnd.ServiceInstanceIdent, "check-fetcher-link")
	if hnd.messageSender == nil {
		spanEmitter.FinishSpanFailed("failed: empty message sender")
		return false
	}
	hnd.lckFetcherRef.Lock()
	defer hnd.lckFetcherRef.Unlock()
	if hnd.fetcherSeriaIdent != qabalwrap.UnknownServiceIdent {
		spanEmitter.FinishSpanSuccess("cached")
		return true
	}
	serialIdent, hasReceiver, ok := hnd.messageSender.ServiceSerialIdentByTextIdent(hnd.fetcherIdent)
	if !ok {
		spanEmitter.FinishSpanFailed("(HTTPContentServeHandler::isFetcherLinkAvailable) service reference unavailable [%s]",
			hnd.fetcherIdent)
		return false
	}
	if !hasReceiver {
		spanEmitter.FinishSpanFailed("(HTTPContentServeHandler::isFetcherLinkAvailable) fetcher receiver unavailable [%s]", hnd.fetcherIdent)
		return false
	}
	hnd.fetcherSeriaIdent = serialIdent
	spanEmitter.FinishSpanSuccess("fetcher serial identifier: %d", serialIdent)
	return true
}

func (hnd *HTTPContentServeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	traceEmitter := hnd.diagnosisEmitter.StartTrace(hnd.ServiceInstanceIdent, "http-content-serve", "fetcher=[ident:%s,serial:%d], http-method=%s, http-url=%s",
		hnd.fetcherIdent, hnd.fetcherSeriaIdent, r.Method, r.URL.String())
	if !hnd.isFetcherLinkAvailable(traceEmitter) {
		http.Error(w, "content link unavailable", http.StatusServiceUnavailable)
		traceEmitter.FinishSpanFailed("fetcher link unavailable")
		return
	}
	transferSlot := hnd.allocateTransferSlot(ctx, traceEmitter)
	if transferSlot == nil {
		http.Error(w, "out of transfer slots", http.StatusServiceUnavailable)
		traceEmitter.FinishSpanFailed("out of transfer slots")
		return
	}
	defer hnd.releaseTransferSlot(traceEmitter, transferSlot)
	transferSlot.serve(traceEmitter, w, r)
	traceEmitter.FinishSpanSuccessWithoutMessage()
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
func (hnd *HTTPContentServeHandler) Setup(
	serviceInstIdent qabalwrap.ServiceInstanceIdentifier,
	diagnosisEmitter *qabalwrap.DiagnosisEmitter,
	certProvider qabalwrap.CertificateProvider) (err error) {
	hnd.ServiceInstanceIdent = serviceInstIdent
	hnd.transferSlotServiceInstIdent = serviceInstIdent + "-slot-s"
	hnd.diagnosisEmitter = diagnosisEmitter
	return
}

// ReceiveMessage implement ServiceProvider interface.
func (hnd *HTTPContentServeHandler) ReceiveMessage(spanEmitter *qabalwrap.TraceEmitter, envelopedMessage *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(hnd.ServiceInstanceIdent, "http-content-serve-recv-msg")
	switch envelopedMessage.MessageContentType() {
	case qabalwrap.MessageContentHTTPContentResponse:
		var req qbw1grpcgen.HTTPContentResponse
		if err = envelopedMessage.Unmarshal(&req); nil != err {
			spanEmitter.FinishSpanFailedLogf("(HTTPContentServeHandler::ReceiveMessage) unmarshal response failed: %v", err)
			return
		}
		hnd.processContentResponse(spanEmitter, &req, envelopedMessage.SourceServiceIdent)
		spanEmitter.FinishSpanSuccessWithoutMessage()
	default:
		spanEmitter.FinishSpanFailedLogf("(HTTPContentServeHandler::ReceiveMessage) unprocess message from %d to %d [content-type=%d].", envelopedMessage.SourceServiceIdent, envelopedMessage.DestinationServiceIdent, envelopedMessage.MessageContentType())
	}
	return
}

// SetMessageSender implement ServiceProvider interface.
func (hnd *HTTPContentServeHandler) SetMessageSender(messageSender qabalwrap.MessageSender) {
	hnd.messageSender = messageSender
}

func (hnd *HTTPContentServeHandler) Stop() {
	traceEmitter := hnd.diagnosisEmitter.StartTraceWithoutMessage(hnd.ServiceInstanceIdent, "stop-http-content-serve")
	defer traceEmitter.FinishSpanSuccessWithoutMessage()
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
