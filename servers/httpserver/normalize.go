package httpserver

import (
	"strings"
)

func normalizeHTTPHost(host string) string {
	i := len(host)
	b := i - 6
	if b < 0 {
		b = 0
	}
	for i--; i >= b; i-- {
		if host[i] == ':' {
			return strings.ToLower(host[:i])
		}
	}
	return strings.ToLower(host)
}
