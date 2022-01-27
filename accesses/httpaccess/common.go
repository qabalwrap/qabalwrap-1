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
	"github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"
)

type baseRelayProvider struct {
	sharedSecret      [32]byte
	messageBuffer     chan *qabalwrap.BaggagedMessage
	messageDispatcher qabalwrap.MessageDispatcher

	serviceInstIdent qabalwrap.ServiceInstanceIdentifier
	diagnosisEmitter *qabalwrap.DiagnosisEmitter
}

func (p *baseRelayProvider) GetServiceInstanceIdentifier() (serviceInstIdent qabalwrap.ServiceInstanceIdentifier) {
	return p.serviceInstIdent
}

func (p *baseRelayProvider) SetMessageDispatcher(spanEmitter *qabalwrap.TraceEmitter, dispatcher qabalwrap.MessageDispatcher) {
	p.messageDispatcher = dispatcher
}

func (p *baseRelayProvider) collectMessagesAsMuchAsPossible(ctx context.Context) (resultQueue []*qabalwrap.BaggagedMessage, resultSize int) {
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

func (p *baseRelayProvider) collectMessages(ctx context.Context, collectTimeout time.Duration) (resultQueue []*qabalwrap.BaggagedMessage, resultSize int) {
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
func (p *baseRelayProvider) packMessages(
	ctx context.Context,
	spanEmitter *qabalwrap.TraceEmitter,
	collectTimeout time.Duration) (resultBinaries []byte, messageCount int, err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "relay-base-pack-messages")
	resultQueue, resultSize := p.collectMessages(ctx, collectTimeout)
	if ctx.Err() != nil {
		spanEmitter.FinishSpanFailed("context error")
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
		spanEmitter.LinkBaggagedMessages(resultQueue)
	}
	result := make([]byte, sha256.Size+4+24, sha256.Size+4+24+len(buf)+secretbox.Overhead)
	var nonce [24]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); nil != err {
		spanEmitter.FinishSpanFailedLogf("(commonRelayProviderBase::packMessages) cannot init nonce: %v", err)
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
	spanEmitter.FinishSpanSuccess("packed %d message into %d bytes", messageCount, len(resultBinaries))
	return
}

func (p *baseRelayProvider) unpackMessages(spanEmitter *qabalwrap.TraceEmitter, b io.Reader) (payload []byte, err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "relay-base-unpack-messages")
	var chksum [sha256.Size]byte
	var sizeBuf [4]byte
	var n int
	if n, err = io.ReadFull(b, chksum[:]); nil != err {
		spanEmitter.FinishSpanFailedLogf("(commonRelayProviderBase::unpackMessages) not enough bytes for digest: %d, %v", n, err)
		return
	}
	if n, err = io.ReadFull(b, sizeBuf[:]); nil != err {
		spanEmitter.FinishSpanFailedLogf("(commonRelayProviderBase::unpackMessages) not enough bytes for size: %d, %v", n, err)
		return
	}
	sizeRaw := binary.LittleEndian.Uint32(sizeBuf[:])
	mask1 := binary.LittleEndian.Uint32(chksum[0:])
	mask2 := binary.LittleEndian.Uint32(chksum[8:])
	sizeReal := int(sizeRaw ^ mask1 ^ mask2)
	if (sizeReal > hardPayloadSizeLimit) || (sizeReal < 24) {
		err = fmt.Errorf("exceed hard HTTP binary payload limit: %d", sizeReal)
		spanEmitter.FinishSpanFailedErr(err)
		return
	}
	totalBuf := make([]byte, 4+sizeReal)
	binary.LittleEndian.PutUint32(totalBuf[0:], uint32(sizeReal))
	if n, err = io.ReadFull(b, totalBuf[4:]); nil != err {
		spanEmitter.FinishSpanFailedLogf("(commonRelayProviderBase::unpackMessages) not enough bytes for payload: %d, expect=%d, %v", n, sizeReal, err)
		return
	}
	versum := sha256.Sum256(totalBuf)
	if chksum != versum {
		err = fmt.Errorf("invalid package checksum: %s vs. %s", base64.RawURLEncoding.EncodeToString(chksum[:]), base64.RawURLEncoding.EncodeToString(versum[:]))
		spanEmitter.FinishSpanFailedErr(err)
		return
	}
	var nonce [24]byte
	copy(nonce[:], totalBuf[4:])
	payloadBytes, ok := secretbox.Open(nil, totalBuf[4+24:], &nonce, &p.sharedSecret)
	if !ok {
		err = ErrPayloadDecrypt
		spanEmitter.FinishSpanFailedErr(err)
		return
	}
	payload = payloadBytes
	spanEmitter.FinishSpanSuccessWithoutMessage()
	return
}

func (p *baseRelayProvider) dispatchMessages(spanEmitter *qabalwrap.TraceEmitter, b io.Reader) (dispatchedMessageCount int, err error) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(p.serviceInstIdent, "relay-base-dispatch-messages")
	payload, err := p.unpackMessages(spanEmitter, b)
	if nil != err {
		spanEmitter.FinishSpanFailedErr(err)
		return
	}
	linkedRemoteTraceIdents := make([]*qbw1diagrpcgen.SpanIdent, 0, 8)
	for len(payload) > 0 {
		var remoteSpanEmitter *qabalwrap.TraceEmitter
		var msg *qabalwrap.EnvelopedMessage
		if remoteSpanEmitter, msg, payload, err = qabalwrap.UnpackBaggagedEnvelopedMessage(payload, p.diagnosisEmitter, "relay-base-dispatch-message"); nil != err {
			spanEmitter.FinishSpanFailedLogf("(commonRelayProviderBase::dispatchMessages) unpack into raw message failed: %v", err)
			return
		}
		if msg != nil {
			p.messageDispatcher.DispatchMessage(remoteSpanEmitter, msg)
			dispatchedMessageCount++
			linkedRemoteTraceIdents = append(linkedRemoteTraceIdents, remoteSpanEmitter.TraceSpanIdent())
		}
	}
	if len(linkedRemoteTraceIdents) > 0 {
		spanEmitter.LinkSpanIdents(linkedRemoteTraceIdents)
	}
	spanEmitter.FinishSpanSuccessWithoutMessage()
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
	p.messageBuffer = make(chan *qabalwrap.BaggagedMessage, messageBufferCount)
	return
}

func (p *baseRelayProvider) blockingEmitMessage(ctx context.Context, spanEmitter *qabalwrap.TraceEmitter, rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	select {
	case p.messageBuffer <- qabalwrap.NewBaggagedMessage(spanEmitter, rawMessage):
		return
	default:
	}
	timer := time.NewTimer(emitMessageTimeout)
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = ErrEmitMessageTimeout
	case p.messageBuffer <- qabalwrap.NewBaggagedMessage(spanEmitter, rawMessage):
	}
	if !timer.Stop() {
		<-timer.C
	}
	return
}

func (p *baseRelayProvider) nonblockingEmitMessage(ctx context.Context, spanEmitter *qabalwrap.TraceEmitter, rawMessage *qabalwrap.EnvelopedMessage) (emitSuccess bool) {
	select {
	case p.messageBuffer <- qabalwrap.NewBaggagedMessage(spanEmitter, rawMessage):
		return true
	default:
	}
	return false
}
