package messageswitch

import (
	"sync/atomic"
	"time"

	md5digest "github.com/go-marshaltemabu/go-md5digest"
	"google.golang.org/protobuf/proto"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

const (
	pingSuccessPeriod = time.Second * 150
	pingEmitPeriod    = time.Second * 100
)

const maxAcceptableMessageCountFreeze = time.Minute * 5

const maxAcceptableHopCount = 7

type messageDispatcher struct {
	relayIndex       int
	relayInst        qabalwrap.RelayProvider
	messageSwitch    *MessageSwitch
	serviceInstIdent qabalwrap.ServiceInstanceIdentifier

	messageCount uint32

	lastKnownServiceIdentsDigest md5digest.MD5Digest

	lastEmitPing    time.Time // check by maintenance thread to see if need send ping
	lastSuccessPing time.Time // check by maintenance thread to see if need send ping

	lastChangedMessageCount  uint32
	lastMessageCountChangeAt time.Time
}

func newMessageDispatcher(
	relayIndex int,
	relayInst qabalwrap.RelayProvider,
	messageSwitch *MessageSwitch) (d *messageDispatcher) {
	return &messageDispatcher{
		relayIndex:               relayIndex,
		relayInst:                relayInst,
		serviceInstIdent:         messageSwitch.ServiceInstanceIdent + "-" + relayInst.GetServiceInstanceIdentifier() + "-msgdispatcher",
		messageSwitch:            messageSwitch,
		lastEmitPing:             time.Now(),
		lastSuccessPing:          time.Now(),
		lastMessageCountChangeAt: time.Now(),
	}
}

func (d *messageDispatcher) shouldEmitHeartbeat() bool {
	return ((time.Since(d.lastSuccessPing) > pingSuccessPeriod) &&
		(time.Since(d.lastEmitPing) > pingEmitPeriod))
}

// Invoked by maintenance routine.
func (d *messageDispatcher) checkLinkTrafficStatus(spanEmitter *qabalwrap.TraceEmitter) bool {
	currentMessageCount := atomic.LoadUint32(&d.messageCount)
	if currentMessageCount != d.lastChangedMessageCount {
		d.lastChangedMessageCount = currentMessageCount
		d.lastMessageCountChangeAt = time.Now()
		spanEmitter.EventInfo("(checkLinkTrafficStatus) message count changed")
		return true
	}
	freezeDuration := time.Since(d.lastMessageCountChangeAt)
	if freezeDuration < maxAcceptableMessageCountFreeze {
		spanEmitter.EventInfo("(checkLinkTrafficStatus) freeze duration less then threshold: %v", freezeDuration)
		return true
	}
	spanEmitter.EventError("(checkLinkTrafficStatus) relay traffic freeze (relay-index=%d, duration=%v)",
		d.relayIndex, freezeDuration)
	return false

}

func (d *messageDispatcher) emitHeartbeatPing(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(d.serviceInstIdent, "emit-heartbeat-ping")
	aux := qbw1grpcgen.HeartbeatPingPong{
		CreateTimestamp: time.Now().UnixNano(),
	}
	buf, err := proto.Marshal(&aux)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(emitHeartbeatPingMessage) cannot marshal heartbeat ping: (relay-%d) %v", d.relayIndex, err)
		return
	}
	m := qabalwrap.NewClearEnvelopedMessage(qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent,
		qabalwrap.MessageContentHeartbeatPing, buf)
	d.lastEmitPing = time.Now()
	if !d.relayInst.NonblockingEmitMessage(spanEmitter, m) {
		spanEmitter.FinishSpanFailedLogf("cannot emit heartbeat message to relay-%d.", d.relayIndex)
		return
	}
	d.lastSuccessPing = time.Now()
	spanEmitter.FinishSpanSuccessWithoutMessage()
}

func (d *messageDispatcher) processPeerKnownServiceIdents(spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(d.serviceInstIdent, "peer-known-service-ident-req")
	var d0 md5digest.MD5Digest
	m.Digest(&d0)
	if d.lastKnownServiceIdentsDigest == d0 {
		spanEmitter.FinishSpanSuccess("peer digest not change")
		return
	}
	d.lastKnownServiceIdentsDigest = d0
	var knownSrvIdents qbw1grpcgen.KnownServiceIdents
	if err := m.Unmarshal(&knownSrvIdents); nil != err {
		spanEmitter.FinishSpanFailedLogf("(messageDispatcher::processPeerKnownServiceIdents) cannot unmarshal known service identifiers for relay-%d: %v", d.relayIndex, err)
		return
	}
	evt := &knownServiceIdentsNotify{
		spanEmitter:        spanEmitter,
		relayIndex:         d.relayIndex,
		knownServiceIdents: &knownSrvIdents,
	}
	d.messageSwitch.notifyPeerKnownServiceIdents <- evt
	spanEmitter.FinishSpanSuccess("emit update to peer")
}

func (d *messageDispatcher) processPeerPing(spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(d.serviceInstIdent, "peer-ping-req")
	var hbPing qbw1grpcgen.HeartbeatPingPong
	if err := m.Unmarshal(&hbPing); nil != err {
		spanEmitter.FinishSpanFailedLogf("(messageDispatcher::processPeerPing) cannot unwrap ping: %v", err)
		return
	}
	aux := qbw1grpcgen.HeartbeatPingPong{
		CreateTimestamp:  hbPing.CreateTimestamp,
		ReceiveTimestamp: time.Now().UnixNano(),
	}
	buf, err := proto.Marshal(&aux)
	if nil != err {
		spanEmitter.FinishSpanFailedLogf("(messageDispatcher::processPeerPing) cannot marshal heartbeat pong: %v", err)
		return
	}
	replyMsg := qabalwrap.NewClearEnvelopedMessage(
		qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent,
		qabalwrap.MessageContentHeartbeatPong, buf)
	if !d.relayInst.NonblockingEmitMessage(spanEmitter, replyMsg) {
		spanEmitter.FinishSpanFailedLogf("(messageDispatcher::processPeerPing) cannot emit ping message (relay-index=%d): %v", d.relayIndex, err)
		return
	}
	spanEmitter.FinishSpanSuccessWithoutMessage()
}

func (d *messageDispatcher) processPeerPong(spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(d.serviceInstIdent, "peer-pong-process")
	var hbPong qbw1grpcgen.HeartbeatPingPong
	if err := m.Unmarshal(&hbPong); nil != err {
		spanEmitter.FinishSpanFailedLogf("(messageDispatcher::processPeerPong) cannot unwrap pong: %v", err)
		return
	}
	costNanoSec := time.Now().UnixNano() - hbPong.CreateTimestamp
	spanEmitter.FinishSpanSuccess("heartbeat ping-pong cost: %d (ns)", costNanoSec)
}

func (d *messageDispatcher) processPeerAllocateServiceIdentsRequest(spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	spanEmitter = spanEmitter.StartSpanWithoutMessage(d.serviceInstIdent, "peer-alloc-service-ident-req")
	if !d.messageSwitch.localServiceRef.IsNormalSerialIdent() {
		spanEmitter.FinishSpanFailedLogf("(messageDispatcher::processPeerAllocateServiceIdentsRequest) cannot forward. local serial is not valid: %d",
			d.messageSwitch.localServiceRef.SerialIdent)
		return
	}
	m.SourceServiceIdent = d.messageSwitch.localServiceRef.SerialIdent
	m.DestinationServiceIdent = qabalwrap.PrimaryMessageSwitchServiceIdent
	if err := d.messageSwitch.forwardClearEnvelopedMessage(spanEmitter, m); nil != err {
		spanEmitter.FinishSpanFailedLogf("(messageDispatcher::processPeerAllocateServiceIdentsRequest) forward failed: %v", err)
	} else {
		spanEmitter.FinishSpanSuccessWithoutMessage()
	}
}

func (d *messageDispatcher) processPeerMessage(spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	switch msgContentType := m.MessageContentType(); msgContentType {
	case qabalwrap.MessageContentKnownServiceIdents:
		d.processPeerKnownServiceIdents(spanEmitter, m)
	case qabalwrap.MessageContentHeartbeatPing:
		d.processPeerPing(spanEmitter, m)
	case qabalwrap.MessageContentHeartbeatPong:
		d.processPeerPong(spanEmitter, m)
	case qabalwrap.MessageContentAllocateServiceIdentsRequest:
		d.processPeerAllocateServiceIdentsRequest(spanEmitter, m)
	default:
		spanEmitter.EventError("(processPeerMessage) unknown content type: %d", msgContentType)
	}
}

func (d *messageDispatcher) DispatchMessage(spanEmitter *qabalwrap.TraceEmitter, m *qabalwrap.EnvelopedMessage) {
	atomic.AddUint32(&d.messageCount, 1)
	if m.DestinationServiceIdent == qabalwrap.AccessProviderPeerServiceIdent {
		d.processPeerMessage(spanEmitter, m)
		return
	}
	if m.RemainHops <= 0 {
		spanEmitter.EventError("message dispatcher: out of remain hop: %d", m.RemainHops)
		return
	}
	if m.RemainHops = m.RemainHops - 1; m.RemainHops > maxAcceptableHopCount {
		m.RemainHops = maxAcceptableHopCount
	}
	if err := d.messageSwitch.forwardEncryptedEnvelopedMessage(spanEmitter, m); nil != err {
		spanEmitter.EventError("cannot forward enveloped message (relay-index=%d): %v", d.relayIndex, err)
	}
}

func (d *messageDispatcher) LinkEstablished(spanEmitter *qabalwrap.TraceEmitter) {
	d.messageSwitch.notifyRelayLinkEstablished <- &relayLinkEstablishNotify{
		spanEmitter: spanEmitter,
		relayIndex:  d.relayIndex,
	}
}
