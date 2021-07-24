package qabalwrap

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	md5digest "github.com/go-marshaltemabu/go-md5digest"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
)

// MessageContentType code type of message contents.
type MessageContentType uint16

// Type code of message contents.
const (
	MessageContentUnknown MessageContentType = iota
	MessageContentKnownServiceIdents
	MessageContentAllocateServiceIdentsRequest
	MessageContentHostCertificateRequest
	MessageContentHostCertificateAssignment
	MessageContentRootCertificateRequest
	MessageContentRootCertificateAssignment
	MessageContentHTTPContentRequest
	MessageContentHTTPContentResponse
	MessageContentHeartbeatPing
	MessageContentHeartbeatPong
	MessageContentTypeBoundary
)

var DefaultMessageHops = [...]int{
	0,
	1, // MessageContentKnownServiceIdents
	5, // MessageContentAllocateServiceIdentsRequest
	3, // MessageContentHostCertificateRequest
	3, // MessageContentHostCertificateAssignment
	3, // MessageContentRootCertificateRequest
	3, // MessageContentRootCertificateAssignment
	5, // MessageContentHTTPContentRequest
	5, // MessageContentHTTPContentResponse
	1, // MessageContentHeartbeatPing
	1, // MessageContentHeartbeatPong
}

// ErrMessageContentTooSmall indicate the message content is too small for content.
var ErrMessageContentTooSmall = errors.New("message content too small")

// EnvelopedMessage contain message in byte slice.
type EnvelopedMessage struct {
	SourceServiceIdent      int
	DestinationServiceIdent int
	RemainHops              int
	MessageContent          []byte
}

// NewClearEnvelopedMessage create message with message content.
func NewClearEnvelopedMessage(
	sourceServiceIdent, destServiceIdent int,
	messageContentType MessageContentType, messageContent []byte) (m *EnvelopedMessage) {
	buf := make([]byte, 2+len(messageContent))
	binary.LittleEndian.PutUint16(buf, uint16(messageContentType))
	copy(buf[2:], messageContent)
	m = &EnvelopedMessage{
		SourceServiceIdent:      sourceServiceIdent,
		DestinationServiceIdent: destServiceIdent,
		RemainHops:              DefaultMessageHops[messageContentType],
		MessageContent:          buf,
	}
	return
}

func MarshalIntoClearEnvelopedMessage(
	sourceServiceIdent, destServiceIdent int,
	messageContentType MessageContentType, messageRef proto.Message) (m *EnvelopedMessage, err error) {
	aux, err := proto.Marshal(messageRef)
	if nil != err {
		return
	}
	m = NewClearEnvelopedMessage(sourceServiceIdent, destServiceIdent, messageContentType, aux)
	return
}

func MarshalIntoEncryptedEnvelopedMessage(
	sourceServiceIdent, destServiceIdent int,
	sharedEncryptKey *[32]byte,
	messageContentType MessageContentType, messageRef proto.Message) (m *EnvelopedMessage, err error) {
	aux, err := proto.Marshal(messageRef)
	if nil != err {
		return
	}
	rawMsg := NewClearEnvelopedMessage(sourceServiceIdent, destServiceIdent, messageContentType, aux)
	aux = nil
	if err = rawMsg.Encrypt(sharedEncryptKey); nil != err {
		return
	}
	m = rawMsg
	return
}

// UnpackEnvelopedMessage fetch RawMessage from given buffer and return remain buffer.
func UnpackEnvelopedMessage(b []byte) (m *EnvelopedMessage, remainBytes []byte, err error) {
	if len(b) < (4 + 6) {
		return
	}
	contentSize := int(binary.LittleEndian.Uint32(b))
	if (contentSize > hardPayloadSizeLimit) || (contentSize < 0) {
		err = fmt.Errorf("unexpect raw message package size: %d", contentSize)
		return
	}
	if len(b) < 10+contentSize {
		err = fmt.Errorf("insufficient buffer for raw message: content-size=%d, buffer-size=%d", contentSize, len(b))
		return
	}
	srcServiceIdent := int(binary.LittleEndian.Uint16(b[4:]))
	dstServiceIdent := int(binary.LittleEndian.Uint16(b[6:]))
	remainHops := int(binary.LittleEndian.Uint16(b[8:]))
	msgContent := b[10 : 10+contentSize]
	if len(b) > 10+contentSize+4+6 {
		remainBytes = b[10+contentSize:]
	}
	m = &EnvelopedMessage{
		SourceServiceIdent:      srcServiceIdent,
		DestinationServiceIdent: dstServiceIdent,
		RemainHops:              remainHops,
		MessageContent:          msgContent,
	}
	return
}

// Pack append binary form of RawMessage into given b.
func (m *EnvelopedMessage) Pack(b []byte) (result []byte) {
	buf := make([]byte, 4+6)
	binary.LittleEndian.PutUint32(buf, uint32(len(m.MessageContent)))
	binary.LittleEndian.PutUint16(buf[4:], uint16(m.SourceServiceIdent))
	binary.LittleEndian.PutUint16(buf[6:], uint16(m.DestinationServiceIdent))
	binary.LittleEndian.PutUint16(buf[8:], uint16(m.RemainHops))
	result = append(append(b, buf...), m.MessageContent...)
	return
}

// PackedLen return bytes resulted by Pack().
func (m *EnvelopedMessage) PackedLen() int {
	return 4 + 6 + len(m.MessageContent)
}

// Encrypt message content.
func (m *EnvelopedMessage) Encrypt(sharedEncryptKey *[32]byte) (err error) {
	aux := make([]byte, 24, 24+len(m.MessageContent)+box.Overhead)
	var nonce [24]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); nil != err {
		return
	}
	copy(aux, nonce[:])
	aux = box.SealAfterPrecomputation(aux, m.MessageContent, &nonce, sharedEncryptKey)
	m.MessageContent = aux
	return
}

// Decrypt message content.
func (m *EnvelopedMessage) Decrypt(sharedDecryptKey *[32]byte) (err error) {
	if len(m.MessageContent) <= 24 {
		err = fmt.Errorf("unexpect raw message content size: %d", len(m.MessageContent))
		return
	}
	var nonce [24]byte
	copy(nonce[:], m.MessageContent[:24])
	buf, ok := box.OpenAfterPrecomputation(nil, m.MessageContent[24:], &nonce, sharedDecryptKey)
	if !ok {
		err = errors.New("decrypt message content failed")
		return
	}
	m.MessageContent = buf
	return
}

// MessageContentType read type code from message content.
// CAUTION: Must decrypt message before invoke this method if message is encrypted.
func (m *EnvelopedMessage) MessageContentType() (t MessageContentType) {
	if len(m.MessageContent) < 2 {
		return MessageContentUnknown
	}
	t = MessageContentType(binary.LittleEndian.Uint16(m.MessageContent))
	if (t < MessageContentUnknown) || (t >= MessageContentTypeBoundary) {
		return MessageContentUnknown
	}
	return
}

// Unmarshal decodes message content into given reference.
// CAUTION: Must decrypt message before invoke this method if message is encrypted.
// CAUTION: Message size is not checked in this method.
// CAUTION: Do NOT call this method if .MessageContentType() does not return known type code.
func (m *EnvelopedMessage) Unmarshal(ref proto.Message) (err error) {
	// *** Ignoring size check. Caller should check message type with .MessageContentType()
	// *** before invoke this method.
	/*
		if len(m.MessageContent) < 2 {
			return ErrMessageContentTooSmall
		}
	*/
	return proto.Unmarshal(m.MessageContent[2:], ref)
}

// Digest checksum message content into given digester.
// CAUTION: Must decrypt message before invoke this method if message is encrypted.
// CAUTION: Message size is not checked in this method.
// CAUTION: Do NOT call this method if .MessageContentType() does not return known type code.
func (m *EnvelopedMessage) Digest(d *md5digest.MD5Digest) {
	if len(m.MessageContent) < 2 {
		return
	}
	d.SumBytes(m.MessageContent[2:])
}
