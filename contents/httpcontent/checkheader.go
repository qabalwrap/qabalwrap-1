package httpcontent

import (
	"net/http"
)

func checkHeaderToken(h http.Header, targetKey, targetToken string) bool {
	values := h.Values(targetKey)
	targetLen := len(targetToken)
	for _, v := range values {
		buf := make([]byte, 0, 16)
		l := len(v)
		for idx := 0; idx < l; idx++ {
			ch := v[idx]
			if ch > 127 {
				buf = buf[:0]
				continue
			}
			var b [2]uint64
			ch64 := uint64(ch)
			b[((ch64 >> 6) & 0x1)] = ch64 & 63
			if ((b[0] & 0x3FFA00000000000) != 0) || ((b[1] & 0x7FFFFFE00000000) != 0) {
				buf = append(buf, ch)
			} else if (b[1] & 0x07FFFFFE) != 0 {
				buf = append(buf, ch-'A'+'a')
			} else if (len(buf) == targetLen) && (string(buf) == targetToken) {
				return true
			} else {
				buf = buf[:0]
			}
		}
		if (len(buf) == targetLen) && (string(buf) == targetToken) {
			return true
		}
	}
	return false
}
