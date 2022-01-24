package httpcontent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net/http"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type tracedHTTPContentResponse struct {
	spanEmitter     *qabalwrap.TraceEmitter
	contentResponse *qbw1grpcgen.HTTPContentResponse
}

type httpContentTransferSlot struct {
	ctx       context.Context
	slotIndex int
	slotIdent int32
	respCh    chan *tracedHTTPContentResponse

	messageSender     qabalwrap.MessageSender
	fetcherSeriaIdent int

	responseIdent int32
}

func newHTTPContentTransferSlot(ctx context.Context, slotIndex int, messageSender qabalwrap.MessageSender, fetcherSeriaIdent int) (s *httpContentTransferSlot) {
	var buf [2]byte
	io.ReadFull(rand.Reader, buf[:])
	slotIdent := int32(((uint32(binary.LittleEndian.Uint16(buf[:])) << 16) & 0x7FFF0000) | 0x00080000 | (uint32(slotIndex) & 0xFFFF))
	s = &httpContentTransferSlot{
		ctx:               ctx,
		slotIndex:         slotIndex,
		slotIdent:         slotIdent,
		respCh:            make(chan *tracedHTTPContentResponse, transferSlotResponseBufferSize),
		messageSender:     messageSender,
		fetcherSeriaIdent: fetcherSeriaIdent,
	}
	return
}

func (slot *httpContentTransferSlot) sendToPeer(spanEmitter *qabalwrap.TraceEmitter, req *qbw1grpcgen.HTTPContentRequest) {
	slot.messageSender.Send(spanEmitter, slot.fetcherSeriaIdent, qabalwrap.MessageContentHTTPContentRequest, req)
}

func (slot *httpContentTransferSlot) serveWebSocket(spanEmitter *qabalwrap.TraceEmitter, w http.ResponseWriter, r *http.Request) {
	spanEmitter = spanEmitter.StartSpan("serve-websocket")
	req0 := qbw1grpcgen.HTTPContentRequest{
		RequestIdent:  slot.slotIdent,
		UrlPath:       r.URL.Path,
		UrlQuery:      r.URL.RawQuery,
		RequestMethod: httpContentRequestMethodWebSocket,
		Headers:       qbw1grpcgen.NewKeyValuesFromHTTPHeader(r.Header),
		IsComplete:    true,
	}
	slot.sendToPeer(spanEmitter, &req0)
	// TODO: impl
	spanEmitter.FinishSpan("failed: not implement yet")
}

func (slot *httpContentTransferSlot) serveRegular(spanEmitter *qabalwrap.TraceEmitter, w http.ResponseWriter, r *http.Request) {
	spanEmitter = spanEmitter.StartSpan("serve-regular")
	reqContentFullBuf := make([]byte, 1024)
	reqContentBuf, reqCompleted, err := readBytesChunk(reqContentFullBuf, r.Body)
	if nil != err {
		http.Error(w, "cannot load request", http.StatusBadRequest)
		spanEmitter.FinishSpan("failed: cannot load request: %v", err)
		return
	}
	req0 := &qbw1grpcgen.HTTPContentRequest{
		RequestIdent:  slot.slotIdent,
		UrlPath:       r.URL.Path,
		UrlQuery:      r.URL.RawQuery,
		RequestMethod: r.Method,
		RequestHost:   r.Host,
		Headers:       qbw1grpcgen.NewKeyValuesFromHTTPHeader(prepareFetchRequestHeader(r)),
		ContentBody:   reqContentBuf,
		IsComplete:    reqCompleted,
	}
	slot.sendToPeer(spanEmitter, req0)
	spanEmitter.EventInfo("(serveRegular) slot %d [%s / %s] remote=<%s> complete=%v, buf-size=%d.", slot.slotIdent, r.Host, r.URL.Path, r.RemoteAddr, reqCompleted, len(reqContentBuf))
	select {
	case tracedResp := <-slot.respCh:
		if (tracedResp == nil) || (tracedResp.contentResponse == nil) {
			http.Error(w, "timeout", http.StatusBadGateway)
			spanEmitter.FinishSpan("failed: (serveRegular) cannot have request response.")
			return
		}
		resp := tracedResp.contentResponse
		slot.responseIdent = resp.ResponseIdent
		spanEmitter.EventInfo("(serveRegular) slot %d bind with response %d.", slot.slotIdent, resp.ResponseIdent)
		if resp.IsComplete {
			if resp.ResultStateCode != 0 {
				w.WriteHeader(int(resp.ResultStateCode))
			} else {
				http.Error(w, "complete without result code.", http.StatusBadGateway)
			}
			if len(resp.ContentBody) > 0 {
				w.Write(resp.ContentBody)
			}
			spanEmitter.FinishSpan("success: complete in one packet")
			return
		}
	case <-slot.ctx.Done():
		http.Error(w, "interrupted", http.StatusBadGateway)
		spanEmitter.FinishSpan("failed: interrupted at request collect stage")
		return
	}
	for !reqCompleted {
		if reqContentBuf, reqCompleted, err = readBytesChunk(reqContentFullBuf, r.Body); nil != err {
			spanEmitter.EventError("(HTTPContentServeHandler) load request failed (remaining parts): %v", err)
			reqCompleted = true
		}
		spanEmitter.EventInfo("(HTTPContentServeHandler) load remaining request content: complete=%v, buf-size=%d", reqCompleted, len(reqContentBuf))
		req0 = &qbw1grpcgen.HTTPContentRequest{
			RequestIdent:  slot.slotIdent,
			ResponseIdent: slot.responseIdent,
			ContentBody:   reqContentBuf,
			IsComplete:    reqCompleted,
		}
		slot.sendToPeer(spanEmitter, req0)
	}
	emitedHeader := false
	for {
		select {
		case tracedResp := <-slot.respCh:
			if (tracedResp == nil) || (tracedResp.contentResponse == nil) {
				if !emitedHeader {
					http.Error(w, "timeout", http.StatusBadGateway)
				}
				spanEmitter.FinishSpanLogError("failed: (serveRegular) cannot have request response.")
				return
			}
			resp := tracedResp.contentResponse
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
				spanEmitter.FinishSpan("success: complete in multiple packet")
				return
			}
		case <-slot.ctx.Done():
			if !emitedHeader {
				http.Error(w, "interrupted", http.StatusBadGateway)
			}
			spanEmitter.FinishSpan("failed: interrupted at response stage")
			return
		}
	}
}

func (slot *httpContentTransferSlot) serve(spanEmitter *qabalwrap.TraceEmitter, w http.ResponseWriter, r *http.Request) {
	if checkHeaderToken(r.Header, "Connection", "upgrade") && checkHeaderToken(r.Header, "Upgrade", "websocket") {
		log.Printf("INFO: having websocket request at [%s]", r.URL.Path)
		slot.serveWebSocket(spanEmitter, w, r)
		return
	}
	slot.serveRegular(spanEmitter, w, r)
}

func (slot *httpContentTransferSlot) release() {
	close(slot.respCh)
}
