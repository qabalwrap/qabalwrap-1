package messageswitch

import (
	"google.golang.org/protobuf/proto"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type messageSender struct {
	serviceSerialIdent int
	messageSwitch      *MessageSwitch
}

func newMessageSender(serviceSerialIdent int, messageSwitch *MessageSwitch) (s *messageSender) {
	return &messageSender{
		serviceSerialIdent: serviceSerialIdent,
		messageSwitch:      messageSwitch,
	}
}

func (s *messageSender) Send(
	spanEmitter *qabalwrap.TraceEmitter,
	destServiceIdent int,
	messageContentType qabalwrap.MessageContentType,
	messageContent proto.Message) {
	buf, err := proto.Marshal(messageContent)
	if nil != err {
		spanEmitter.EventErrorf("(messageSender::Send) cannot marshal message (service-serial=%d): %v", s.serviceSerialIdent, err)
		return
	}
	msg := qabalwrap.NewClearEnvelopedMessage(s.serviceSerialIdent, destServiceIdent, messageContentType, buf)
	if err = s.messageSwitch.forwardClearEnvelopedMessage(spanEmitter, msg); nil != err {
		spanEmitter.EventErrorf("(messageSender::Send) cannot send message (service-serial: src=%d, dest%d): %v", s.serviceSerialIdent, destServiceIdent, err)
	}
}

func (s *messageSender) ServiceSerialIdentByTextIdent(textIdent string) (serialIdent int, hasReceiver, ok bool) {
	conn := s.messageSwitch.crossBar.getServiceConnectByTextIdent(textIdent)
	if conn == nil {
		return
	}
	hasReceiver = conn.linkAvailable()
	serialIdent = conn.SerialIdent
	ok = true
	return
}
