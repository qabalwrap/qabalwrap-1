package httpaccess

import (
	"errors"
	"net/http"
)

func httpBadRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "400 bad request", http.StatusBadRequest)
}

// ErrPayloadDecrypt indicate failed on decrypting payload.
var ErrPayloadDecrypt = errors.New("decrypt failed")

// ErrEmitMessageTimeout indicate timeout occurs on message emit.
var ErrEmitMessageTimeout = errors.New("emit message timeout")
