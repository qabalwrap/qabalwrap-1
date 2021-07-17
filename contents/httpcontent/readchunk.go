package httpcontent

import (
	"io"
	"log"
)

func readBytesChunk(fullBuf []byte, bodyReader io.ReadCloser) (loadedBuf []byte, completed bool, err error) {
	loadedBuf = fullBuf
	var n int
	if n, err = bodyReader.Read(loadedBuf); nil != err {
		if err == io.EOF {
			completed = true
			if n <= 0 {
				loadedBuf = nil
			} else {
				loadedBuf = loadedBuf[:n]
			}
			err = nil
		} else {
			log.Printf("ERROR: (readBytesChunk) load request failed: %v", err)
		}
	} else if n > 0 {
		loadedBuf = loadedBuf[:n]
	} else {
		loadedBuf = nil
	}
	return
}
