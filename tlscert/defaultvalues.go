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

// const certificateRequestExpireSeconds = 180
