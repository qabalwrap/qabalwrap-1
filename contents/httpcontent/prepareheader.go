package httpcontent

import (
	"log"
	"net"
	"net/http"
)

const (
	headerKeyXForwardedFor = "X-Forwarded-For"
	headerKeyForwarded     = "Forwarded"
)

func prepareFetchRequestHeader(r *http.Request) (reqHeader http.Header) {
	remoteAddrOnly, _, err := net.SplitHostPort(r.RemoteAddr)
	if nil != err {
		log.Printf("WARN: (prepareFetchRequestHeader) cannot split address from RemoteAddr: [%s]", r.RemoteAddr)
		remoteAddrOnly = r.RemoteAddr
	}
	if remoteAddrOnly == "" {
		log.Printf("WARN: (prepareFetchRequestHeader) cannot have remote address for request: RemoteAddr=[%s]", r.RemoteAddr)
		return r.Header
	}
	reqHeader = r.Header.Clone()
	forwardForAddr := remoteAddrOnly
	if existedForwardForAddr := r.Header.Get(headerKeyXForwardedFor); existedForwardForAddr != "" {
		forwardForAddr = existedForwardForAddr + ", " + forwardForAddr
	}
	reqHeader.Set(headerKeyXForwardedFor, forwardForAddr)
	forwardedValue := "for=" + remoteAddrOnly
	if existedForwarded := r.Header.Get(headerKeyForwarded); existedForwarded != "" {
		forwardedValue = existedForwarded + ", " + forwardedValue
	}
	reqHeader.Set(headerKeyForwarded, forwardedValue)
	return
}
