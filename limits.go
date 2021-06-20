package qabalwrap

import (
	"time"
)

// Limitations of payload size.
const (
	hardPayloadSizeLimit = 64 * 1024
	softPayloadSizeLimit = 12 * 1024
)

const (
	nonEmptyRawMessageCollectTimeout = time.Millisecond * 50

	fastEmptyRawMessageCollectTimeout = time.Millisecond * 500
	slowEmptyRawMessageCollectTimeout = time.Second * 3

	emitRawMessageTimeout = time.Second * 10
)
