package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
	"time"

	utilhttphandlers "github.com/yinyin/go-util-http-handlers"
)

type helloHTTPResponse struct {
	MessageText string
	StartAt     time.Time
	Host        string
	Path        string
	Headers     map[string][]string
}

type helloHTTPHandler struct {
	messageText string
	startAt     time.Time
}

func (hnd *helloHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	utilhttphandlers.JSONResponseWithStatusOK(w, &helloHTTPResponse{
		MessageText: hnd.messageText,
		StartAt:     hnd.startAt,
		Host:        r.Host,
		Path:        r.URL.Path,
		Headers:     r.Header,
	})
}

func parseCommandParam() (listenAt string, messageText string, err error) {
	flag.StringVar(&listenAt, "listen", ":8080", "address:port to listen")
	flag.StringVar(&messageText, "message", "Hello", "message to show in response")
	flag.Parse()
	if listenAt == "" {
		return "", "", errors.New("require option `listen` is empty")
	}
	if messageText == "" {
		return "", "", errors.New("require option `message` is empty")
	}
	return
}

func main() {
	listenAt, messageText, err := parseCommandParam()
	if nil != err {
		log.Fatalf("invalid command option for hello-httpd: %v", err)
		return
	}
	hnd := &helloHTTPHandler{
		messageText: messageText,
		startAt:     time.Now(),
	}
	log.Printf("INFO: start (listen on: %s).", listenAt)
	if err = http.ListenAndServe(listenAt, hnd); nil != err {
		log.Printf("WARN: http.ListenAndServe return no nil result: %v", err)
	}
	log.Print("INFO: stopped.")
}
