package qbw1grpcgen

import (
	"net/http"
)

func NewKeyValuesFromHTTPHeader(h http.Header) (x []*KeyValues) {
	nv := 0
	for _, values := range h {
		nv += len(values)
	}
	x = make([]*KeyValues, 0, len(h))
	allValues := make([]string, nv)
	for k, values := range h {
		n := copy(allValues, values)
		dupVals := allValues[:n:n]
		allValues = allValues[n:]
		aux := &KeyValues{
			Key:    k,
			Values: dupVals,
		}
		x = append(x, aux)
	}
	return
}

func fromKeyValuesToHTTPHeader(x []*KeyValues) (h http.Header) {
	if len(x) == 0 {
		return
	}
	nv := 0
	for _, kv := range x {
		nv += len(kv.Values)
	}
	h = make(http.Header, len(x))
	allValues := make([]string, nv)
	for _, kv := range x {
		n := copy(allValues, kv.Values)
		values := allValues[:n:n]
		allValues = allValues[n:]
		h[kv.Key] = values
	}
	return
}

func (x *HTTPContentRequest) GetHeadersHTTPHeader() (h http.Header) {
	return fromKeyValuesToHTTPHeader(x.Headers)
}

func (x *HTTPContentResponse) GetHeadersHTTPHeader() (h http.Header) {
	return fromKeyValuesToHTTPHeader(x.Headers)
}
