package httpcontent

import (
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var websocketDefaultDialer = &websocket.Dialer{
	Proxy:            http.ProxyFromEnvironment,
	HandshakeTimeout: 45 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

var httpDefaultClient *http.Client

func init() {
	transportInst := http.DefaultTransport.(*http.Transport).Clone()
	transportInst.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	httpDefaultClient = &http.Client{
		CheckRedirect: checkRedirect,
		Transport:     transportInst,
	}
}

func findRequestTargetHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	viaSize := len(via)
	if viaSize >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if viaSize > 1 {
		lastReq := via[viaSize-1]
		log.Printf("TRACE: (checkRedirect) redirect from [%s](%d) to [%s].", lastReq.URL.String(), viaSize, req.URL.String())
		if findRequestTargetHost(req) == findRequestTargetHost(lastReq) {
			return http.ErrUseLastResponse
		}
	} else {
		log.Printf("TRACE: (checkRedirect) redirect to [%s] with empty via.", req.URL.String())
	}
	return nil
}
