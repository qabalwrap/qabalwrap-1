package tlscert

import (
	"time"
)

const (
	commonNameRootCA            = "QabalWrap Root CA"
	expireAheadDuration         = time.Hour * 7 * 24
	rootCAValidDuration         = time.Hour * 24 * 366 * 20
	hostCertValidDuration       = time.Hour * 24 * 366
	selfSignedCertValidDuration = time.Hour * 8
)

const (
	defaultCountry        = "XQ"
	defaultOrganization   = "Snack Oil Co."
	defaultTLSHostAddress = "default-85f45c9e.example.net"
)

// const certificateRequestExpireSeconds = 180
