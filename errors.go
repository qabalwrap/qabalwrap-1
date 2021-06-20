package qabalwrap

import (
	"errors"
)

// ErrRequestUnpackInsufficientBuffer indicate given buffer too small for request data.
var ErrRequestUnpackInsufficientBuffer = errors.New("given buffer too small for request")

// ErrEmptyIdentifier indicate given identifier is empty or totally invalid.
var ErrEmptyIdentifier = errors.New("given service identifier is empty or contain none valid character")

// ErrEmitMessageTimeout indicate timeout occurs on message emit.
var ErrEmitMessageTimeout = errors.New("emit message timeout")
