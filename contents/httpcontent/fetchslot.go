package httpcontent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"net/url"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

type httpContentFetchSlot struct {
	ctx             context.Context
	cancel          context.CancelFunc
	upstreamFetcher *HTTPContentFetcher
	slotIndex       int
	slotIdent       int32
	reqCh           chan *qbw1grpcgen.HTTPContentRequest
	msgSender       qabalwrap.MessageSender
	peerSerialIdent int
	requestIdent    int32
}

func newHTTPContentFetchSlot(ctx context.Context, upstreamFetcher *HTTPContentFetcher, slotIndex int, msgSender qabalwrap.MessageSender, srcSerialIdent int, requestIdent int32) (s *httpContentFetchSlot) {
	var buf [2]byte
	io.ReadFull(rand.Reader, buf[:])
	slotIdent := int32(((uint32(binary.LittleEndian.Uint16(buf[:])) << 16) & 0x7FFF0000) | 0x00010000 | (uint32(slotIndex) & 0xFFFF))
	ctx, cancel := context.WithCancel(ctx)
	s = &httpContentFetchSlot{
		ctx:             ctx,
		cancel:          cancel,
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
	slot.msgSender.Send(slot.peerSerialIdent, qabalwrap.MessageContentHTTPContentResponse, resp)
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

func (slot *httpContentFetchSlot) runRegular(targetURL *url.URL, req *qbw1grpcgen.HTTPContentRequest) {
	var httpReq *http.Request
	var err error
	if req.IsComplete {
		if len(req.ContentBody) > 0 {
			httpReq, err = http.NewRequestWithContext(slot.ctx, req.RequestMethod, targetURL.String(), bytes.NewReader(req.ContentBody))
			// log.Printf("TRACE: (httpContentFetchSlot::run) request method=%s, url=[%s] with content (len=%d)", req.RequestMethod, targetURL.String(), len(req.ContentBody))
		} else {
			httpReq, err = http.NewRequestWithContext(slot.ctx, req.RequestMethod, targetURL.String(), nil)
			// log.Printf("TRACE: (httpContentFetchSlot::run) request method=%s, url=[%s] without content", req.RequestMethod, targetURL.String())
		}
	} else {
		reqBodyReader, reqBodyWriter := io.Pipe()
		httpReq, err = http.NewRequestWithContext(slot.ctx, req.RequestMethod, targetURL.String(), reqBodyReader)
		// log.Printf("TRACE: (httpContentFetchSlot::run) request method=%s, url=[%s] with large content", req.RequestMethod, targetURL.String())
		go func() {
			if len(req.ContentBody) > 0 {
				reqBodyWriter.Write(req.ContentBody)
			}
			for {
				req1 := <-slot.reqCh
				if req1 == nil {
					// log.Printf("TRACE: (httpContentFetchSlot::run) request method=%s, url=[%s] empty request-1", req.RequestMethod, targetURL.String())
					break
				}
				if len(req1.ContentBody) > 0 {
					// log.Printf("TRACE: (httpContentFetchSlot::run) request method=%s, url=[%s] content part (len=%d)", req.RequestMethod, targetURL.String(), len(req1.ContentBody))
					reqBodyWriter.Write(req1.ContentBody)
				}
				if req1.IsComplete {
					// log.Printf("TRACE: (httpContentFetchSlot::run) request method=%s, url=[%s] request complete", req.RequestMethod, targetURL.String())
					break
				}
			}
			// log.Printf("TRACE: (httpContentFetchSlot::run) request method=%s, url=[%s] leaving content write", req.RequestMethod, targetURL.String())
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
	respContentFullBuf := make([]byte, 1024*16)
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

func (slot *httpContentFetchSlot) run(req *qbw1grpcgen.HTTPContentRequest) {
	defer slot.close()
	targetURL := slot.upstreamFetcher.targetBaseURL
	targetURL.Path = req.UrlPath
	targetURL.RawQuery = req.UrlQuery
	if req.RequestMethod == httpContentRequestMethodWebSocket {
		slot.runWebSocket(&targetURL, req.GetHeadersHTTPHeader())
	} else {
		slot.runRegular(&targetURL, req)
	}
}

func (slot *httpContentFetchSlot) release() {
	close(slot.reqCh)
}

func (slot *httpContentFetchSlot) close() {
	slot.cancel()
	slot.upstreamFetcher.releaseFetchSlot(slot)
}
