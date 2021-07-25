package qabalwrap

import (
	"errors"
)

// ErrDeprecated indicate requested feature is deprecated and not implemented.
var ErrDeprecated = errors.New("deprecated")

// ErrWontImplement indicate requested feature will not implement for some reason.
var ErrWontImplement = errors.New("will not implement")

// ErrRequestUnpackInsufficientBuffer indicate given buffer too small for request data.
var ErrRequestUnpackInsufficientBuffer = errors.New("given buffer too small for request")

// ErrEmptyIdentifier indicate given identifier is empty or totally invalid.
var ErrEmptyIdentifier = errors.New("given service identifier is empty or contain none valid character")
