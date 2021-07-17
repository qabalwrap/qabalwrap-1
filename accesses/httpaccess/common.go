package httpaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type baseRelayProvider struct {
	sharedSecret      [32]byte
	messageBuffer     chan *qabalwrap.EnvelopedMessage
	messageDispatcher *qabalwrap.MessageDispatcher
}

func (p *baseRelayProvider) SetMessageDispatcher(dispatcher *qabalwrap.MessageDispatcher) {
	p.messageDispatcher = dispatcher
}

func (p *baseRelayProvider) collectMessagesAsMuchAsPossible(ctx context.Context) (resultQueue []*qabalwrap.EnvelopedMessage, resultSize int) {
	timer := time.NewTimer(nonEmptyMessageCollectTimeout)
	for resultSize < softPayloadSizeLimit {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case rawMsg := <-p.messageBuffer:
			resultQueue = append(resultQueue, rawMsg)
			resultSize += rawMsg.PackedLen()
		}
	}
	if !timer.Stop() {
		<-timer.C
	}
	return
}

func (p *baseRelayProvider) collectMessages(ctx context.Context, collectTimeout time.Duration) (resultQueue []*qabalwrap.EnvelopedMessage, resultSize int) {
	startTimestamp := time.Now()
	if resultQueue, resultSize = p.collectMessagesAsMuchAsPossible(ctx); resultSize > 0 {
		return
	}
	for resultSize < softPayloadSizeLimit {
		if resultQueue, resultSize = p.collectMessagesAsMuchAsPossible(ctx); resultSize > 0 {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(startTimestamp) > collectTimeout {
			return
		}
	}
	return
}

// packMessages collect and encode waiting raw messages in given collect timeout.
func (p *baseRelayProvider) packMessages(ctx context.Context, collectTimeout time.Duration) (resultBinaries []byte, messageCount int, err error) {
	resultQueue, resultSize := p.collectMessages(ctx, collectTimeout)
	if ctx.Err() != nil {
		return
	}
	var buf []byte
	if resultSize == 0 {
		buf = make([]byte, 4)
	} else {
		buf = make([]byte, 0, resultSize)
		for _, rawMsg := range resultQueue {
			buf = rawMsg.Pack(buf)
		}
		messageCount = len(resultQueue)
	}
	result := make([]byte, sha256.Size+4+24, sha256.Size+4+24+len(buf)+secretbox.Overhead)
	var nonce [24]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::packMessages) cannot init nonce: %v", err)
		return
	}
	copy(result[sha256.Size+4:], nonce[:])
	result = secretbox.Seal(result, buf, &nonce, &p.sharedSecret)
	sizeReal := len(result) - (sha256.Size + 4)
	binary.LittleEndian.PutUint32(result[sha256.Size:], uint32(sizeReal))
	chksum := sha256.Sum256(result[sha256.Size:])
	copy(result, chksum[:])
	mask1 := binary.LittleEndian.Uint32(chksum[0:])
	mask2 := binary.LittleEndian.Uint32(chksum[8:])
	sizeRaw := uint32(sizeReal) ^ mask1 ^ mask2
	binary.LittleEndian.PutUint32(result[sha256.Size:], uint32(sizeRaw))
	resultBinaries = result
	return
}

func (p *baseRelayProvider) unpackMessages(b io.Reader) (payload []byte, err error) {
	var chksum [sha256.Size]byte
	var sizeBuf [4]byte
	var n int
	if n, err = io.ReadFull(b, chksum[:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::unpackMessages) not enough bytes for digest: %d, %v", n, err)
		return
	}
	if n, err = io.ReadFull(b, sizeBuf[:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::unpackMessages) not enough bytes for size: %d, %v", n, err)
		return
	}
	sizeRaw := binary.LittleEndian.Uint32(sizeBuf[:])
	mask1 := binary.LittleEndian.Uint32(chksum[0:])
	mask2 := binary.LittleEndian.Uint32(chksum[8:])
	sizeReal := int(sizeRaw ^ mask1 ^ mask2)
	if (sizeReal > hardPayloadSizeLimit) || (sizeReal < 24) {
		err = fmt.Errorf("exceed hard HTTP binary payload limit: %d", sizeReal)
		return
	}
	totalBuf := make([]byte, 4+sizeReal)
	binary.LittleEndian.PutUint32(totalBuf[0:], uint32(sizeReal))
	if n, err = io.ReadFull(b, totalBuf[4:]); nil != err {
		log.Printf("ERROR: (commonRelayProviderBase::unpackMessages) not enough bytes for payload: %d, expect=%d, %v", n, sizeReal, err)
		return
	}
	versum := sha256.Sum256(totalBuf)
	if chksum != versum {
		err = fmt.Errorf("invalid package checksum: %s vs. %s", base64.RawURLEncoding.EncodeToString(chksum[:]), base64.RawURLEncoding.EncodeToString(versum[:]))
	}
	var nonce [24]byte
	copy(nonce[:], totalBuf[4:])
	payloadBytes, ok := secretbox.Open(nil, totalBuf[4+24:], &nonce, &p.sharedSecret)
	if !ok {
		err = ErrPayloadDecrypt
		return
	}
	payload = payloadBytes
	return
}

func (p *baseRelayProvider) dispatchMessages(b io.Reader) (dispatchedMessageCount int, err error) {
	payload, err := p.unpackMessages(b)
	if nil != err {
		return
	}
	for len(payload) > 0 {
		var rawMsg *qabalwrap.EnvelopedMessage
		if rawMsg, payload, err = qabalwrap.UnpackRawMessage(payload); nil != err {
			log.Printf("ERROR: (commonRelayProviderBase::dispatchMessages) unpack into raw message failed: %v", err)
			return
		}
		if rawMsg != nil {
			p.messageDispatcher.DispatchRawMessage(rawMsg)
			dispatchedMessageCount++
		}
	}
	return
}

func (p *baseRelayProvider) initBaseRelayProvider(sharedSecretText string, messageBufferCount int) (err error) {
	if sharedSecretText == "" {
		if _, err = io.ReadFull(rand.Reader, p.sharedSecret[:]); nil != err {
			log.Printf("ERROR: (commonRelayProviderBase) cannot generate shared key: %v", err)
			return
		}
		log.Printf("INFO: (commonRelayProviderBase) shared key generated: [ %s ]",
			base64.RawURLEncoding.EncodeToString(p.sharedSecret[:]))
	} else {
		var buf []byte
		if buf, err = base64.RawURLEncoding.DecodeString(sharedSecretText); nil != err {
			log.Printf("ERROR: (commonRelayProviderBase) cannot unpack shared key: %v", err)
			return
		}
		if len(buf) < 32 {
			log.Printf("WARN: (commonRelayProviderBase) short shared key: %d (< 32)", len(buf))
		}
		copy(p.sharedSecret[:], buf)
	}
	p.messageBuffer = make(chan *qabalwrap.EnvelopedMessage, messageBufferCount)
	return
}

func (p *baseRelayProvider) emitMessage(ctx context.Context, rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	select {
	case p.messageBuffer <- rawMessage:
		return
	default:
	}
	timer := time.NewTimer(emitMessageTimeout)
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = ErrEmitMessageTimeout
	case p.messageBuffer <- rawMessage:
	}
	if !timer.Stop() {
		<-timer.C
	}
	return
}
