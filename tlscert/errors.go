package tlscert

import (
	"errors"
)

var errNotValidRootCA = errors.New("not valid root CA")

var errCertificateRequestTimeout = errors.New("cert request timeout")
