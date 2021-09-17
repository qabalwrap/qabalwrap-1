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

type httpContentTransferSlot struct {
	ctx       context.Context
	slotIndex int
	slotIdent int32
	respCh    chan *qbw1grpcgen.HTTPContentResponse

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
		respCh:            make(chan *qbw1grpcgen.HTTPContentResponse, transferSlotResponseBufferSize),
		messageSender:     messageSender,
		fetcherSeriaIdent: fetcherSeriaIdent,
	}
	return
}

func (slot *httpContentTransferSlot) sendToPeer(req *qbw1grpcgen.HTTPContentRequest) {
	slot.messageSender.Send(slot.fetcherSeriaIdent, qabalwrap.MessageContentHTTPContentRequest, req)
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
		Headers:       qbw1grpcgen.NewKeyValuesFromHTTPHeader(prepareFetchRequestHeader(r)),
		ContentBody:   reqContentBuf,
		IsComplete:    reqCompleted,
	}
	slot.sendToPeer(req0)
	log.Printf("TRACE: (serveRegular) slot %d [%s / %s] remote=<%s> complete=%v, buf-size=%d.", slot.slotIdent, r.Host, r.URL.Path, r.RemoteAddr, reqCompleted, len(reqContentBuf))
	select {
	case resp := <-slot.respCh:
		if resp == nil {
			http.Error(w, "timeout", http.StatusBadGateway)
			log.Print("ERROR: (serveRegular) cannot have request response.")
			return
		}
		slot.responseIdent = resp.ResponseIdent
		log.Printf("TRACE: (serveRegular) slot %d bind with response %d.", slot.slotIdent, resp.ResponseIdent)
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
		// log.Printf("TRACE: (HTTPContentServeHandler) load remaining request content: complete=%v, buf-size=%d", reqCompleted, len(reqContentBuf))
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
