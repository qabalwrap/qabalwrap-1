package qabalwrap

import (
	"strconv"
)

type ServiceTypeIdentifier int

const (
	ServiceTypeUnknown ServiceTypeIdentifier = iota
	ServiceTypeMessageSwitch
	ServiceTypeAccessProvider
	ServiceTypeHTTPServer
	ServiceTypeHTTPFetcher
	ServiceTypeHTTPEdge
)

const (
	ServiceTypeTextUnknown        = "unknown-service"
	ServiceTypeTextMessageSwitch  = "message-switch"
	ServiceTypeTextAccessProvider = "access-provider"
	ServiceTypeTextHTTPServer     = "http-server"
	ServiceTypeTextHTTPFetcher    = "http-fetcher"
	ServiceTypeTextHTTPEdge       = "http-edge"
)

var serviceTypeText = []string{
	ServiceTypeTextUnknown,
	ServiceTypeTextMessageSwitch,
	ServiceTypeTextAccessProvider,
	ServiceTypeTextHTTPServer,
	ServiceTypeTextHTTPFetcher,
	ServiceTypeTextHTTPEdge,
}

func (t ServiceTypeIdentifier) String() string {
	if (int(t) >= len(serviceTypeText)) || (int(t) < 0) {
		return strconv.FormatInt(int64(t), 10)
	}
	return serviceTypeText[t]
}
