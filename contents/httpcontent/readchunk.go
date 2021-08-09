package httpcontent

import (
	"io"
	"log"
	"time"
)

const maxChunkReadDelay = time.Millisecond * 100

func readBytesChunk(fullBuf []byte, bodyReader io.ReadCloser) (loadedBuf []byte, completed bool, err error) {
	remain := len(fullBuf)
	offset := 0
	startAt := time.Now()
	for (remain > 0) && (time.Since(startAt) < maxChunkReadDelay) {
		var n int
		if n, err = bodyReader.Read(fullBuf[offset:]); nil != err {
			if err == io.EOF {
				completed = true
				if n > 0 {
					offset += n
				}
				if offset > 0 {
					loadedBuf = fullBuf[:offset]
				}
				err = nil
			} else {
				log.Printf("ERROR: (readBytesChunk) load request failed: %v", err)
			}
			return
		} else if n > 0 {
			offset += n
			remain -= n
		}
	}
	if offset > 0 {
		loadedBuf = fullBuf[:offset]
	}
	return
}
