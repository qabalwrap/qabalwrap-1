package httpaccess

import (
	"time"
)

// Limitations of payload size.
const (
	hardPayloadSizeLimit = 64 * 1024
	softPayloadSizeLimit = 12 * 1024
)

const (
	nonEmptyMessageCollectTimeout = time.Millisecond * 50

	fastEmptyMessageCollectTimeout = time.Millisecond * 500
	slowEmptyMessageCollectTimeout = time.Second * 3

	emitMessageTimeout = time.Second * 10
)
