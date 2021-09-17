package httpcontent

import (
	"crypto/tls"
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

func checkRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}
