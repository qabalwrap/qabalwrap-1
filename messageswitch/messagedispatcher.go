package messageswitch

import (
	"log"
	"sync/atomic"
	"time"

	md5digest "github.com/go-marshaltemabu/go-md5digest"
	"google.golang.org/protobuf/proto"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

const pingEmitPeriod = time.Second * 100

const maxAcceptablePingPongLostSecond = 300

const maxAcceptableHopCount = 7

type messageDispatcher struct {
	relayIndex    int
	relayInst     qabalwrap.RelayProvider
	messageSwitch *MessageSwitch

	lastKnownServiceIdentsDigest md5digest.MD5Digest

	lastEmitPing time.Time // check by maintenance thread to see if need send ping

	lastReceivePing int64
	lastReceivePong int64
}

func newMessageDispatcher(
	relayIndex int,
	relayInst qabalwrap.RelayProvider,
	messageSwitch *MessageSwitch) (d *messageDispatcher) {
	return &messageDispatcher{
		relayIndex:      relayIndex,
		relayInst:       relayInst,
		messageSwitch:   messageSwitch,
		lastEmitPing:    time.Now(),
		lastReceivePing: time.Now().Unix(),
		lastReceivePong: time.Now().Unix(),
	}
}

func (d *messageDispatcher) shouldEmitHeartbeat() bool {
	return (time.Since(d.lastEmitPing) > pingEmitPeriod)
}

func (d *messageDispatcher) checkLinkHeartbeat() bool {
	currentTimestamp := time.Now().Unix()
	if t := (currentTimestamp - atomic.LoadInt64(&d.lastReceivePing)); t > maxAcceptablePingPongLostSecond {
		log.Printf("ERROR: (messageDispatcher::checkLinkHeartbeat) not receiving ping %d seconds.", t)
		return false
	}
	if t := (currentTimestamp - atomic.LoadInt64(&d.lastReceivePong)); t > maxAcceptablePingPongLostSecond {
		log.Printf("ERROR: (messageDispatcher::checkLinkHeartbeat) not receiving pong %d seconds.", t)
		return false
	}
	return true
}

func (d *messageDispatcher) emitHeartbeatPing() {
	aux := qbw1grpcgen.HeartbeatPingPong{
		CreateTimestamp: time.Now().UnixNano(),
	}
	buf, err := proto.Marshal(&aux)
	if nil != err {
		log.Printf("ERROR: (emitHeartbeatPingMessage) cannot marshal heartbeat ping: %v", err)
		return
	}
	m := qabalwrap.NewClearEnvelopedMessage(qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent,
		qabalwrap.MessageContentHeartbeatPing, buf)
	if !d.relayInst.NonblockingEmitMessage(m) {
		log.Printf("WARN: cannot emit heartbeat message to relay-%d.", d.relayIndex)
	}
	d.lastEmitPing = time.Now()
}

func (d *messageDispatcher) processPeerKnownServiceIdents(m *qabalwrap.EnvelopedMessage) {
	var d0 md5digest.MD5Digest
	m.Digest(&d0)
	if d.lastKnownServiceIdentsDigest == d0 {
		return
	}
	d.lastKnownServiceIdentsDigest = d0
	var knownSrvIdents qbw1grpcgen.KnownServiceIdents
	if err := m.Unmarshal(&knownSrvIdents); nil != err {
		log.Printf("ERROR: (messageDispatcher::processPeerKnownServiceIdents) cannot unmarshal known service identifiers for relay-%d: %v", d.relayIndex, err)
		return
	}
	evt := &knownServiceIdentsNotify{
		relayIndex:         d.relayIndex,
		knownServiceIdents: &knownSrvIdents,
	}
	d.messageSwitch.notifyPeerKnownServiceIdents <- evt
}

func (d *messageDispatcher) processPeerPing(m *qabalwrap.EnvelopedMessage) {
	var hbPing qbw1grpcgen.HeartbeatPingPong
	if err := m.Unmarshal(&hbPing); nil != err {
		log.Printf("ERROR: (messageDispatcher::processPeerPing) cannot unwrap ping: %v", err)
		return
	}
	aux := qbw1grpcgen.HeartbeatPingPong{
		CreateTimestamp:  hbPing.CreateTimestamp,
		ReceiveTimestamp: time.Now().UnixNano(),
	}
	buf, err := proto.Marshal(&aux)
	if nil != err {
		log.Printf("ERROR: (messageDispatcher::processPeerPing) cannot marshal heartbeat pong: %v", err)
		return
	}
	replyMsg := qabalwrap.NewClearEnvelopedMessage(
		qabalwrap.AccessProviderPeerServiceIdent, qabalwrap.AccessProviderPeerServiceIdent,
		qabalwrap.MessageContentHeartbeatPong, buf)
	if !d.relayInst.NonblockingEmitMessage(replyMsg) {
		log.Printf("ERROR: (messageDispatcher::processPeerPing) cannot emit ping message (relay-index=%d): %v", d.relayIndex, err)
		return
	}
	atomic.StoreInt64(&d.lastReceivePing, time.Now().Unix())
}

func (d *messageDispatcher) processPeerPong(m *qabalwrap.EnvelopedMessage) {
	var hbPong qbw1grpcgen.HeartbeatPingPong
	if err := m.Unmarshal(&hbPong); nil != err {
		log.Printf("ERROR: (messageDispatcher::processPeerPong) cannot unwrap pong: %v", err)
		return
	}
	costNanoSec := time.Now().UnixNano() - hbPong.CreateTimestamp
	log.Printf("INFO: heartbeat ping-pong cost: %d (ns)", costNanoSec)
	atomic.StoreInt64(&d.lastReceivePong, time.Now().Unix())
}

func (d *messageDispatcher) processPeerAllocateServiceIdentsRequest(m *qabalwrap.EnvelopedMessage) {
	if !d.messageSwitch.localServiceRef.IsNormalSerialIdent() {
		log.Printf("WARN: (messageDispatcher::processPeerAllocateServiceIdentsRequest) cannot forward. local serial is not valid: %d",
			d.messageSwitch.localServiceRef.SerialIdent)
		return
	}
	m.SourceServiceIdent = d.messageSwitch.localServiceRef.SerialIdent
	m.DestinationServiceIdent = 0
	if err := d.messageSwitch.forwardClearEnvelopedMessage(m); nil != err {
		log.Printf("ERROR: (messageDispatcher::processPeerAllocateServiceIdentsRequest) forward failed: %v", err)
	}
}

func (d *messageDispatcher) processPeerMessage(m *qabalwrap.EnvelopedMessage) {
	switch m.MessageContentType() {
	case qabalwrap.MessageContentKnownServiceIdents:
		d.processPeerKnownServiceIdents(m)
	case qabalwrap.MessageContentHeartbeatPing:
		d.processPeerPing(m)
	case qabalwrap.MessageContentHeartbeatPong:
		d.processPeerPong(m)
	case qabalwrap.MessageContentAllocateServiceIdentsRequest:
		d.processPeerAllocateServiceIdentsRequest(m)
	}
}

func (d *messageDispatcher) DispatchMessage(m *qabalwrap.EnvelopedMessage) {
	if m.DestinationServiceIdent == qabalwrap.AccessProviderPeerServiceIdent {
		d.processPeerMessage(m)
		return
	}
	if m.RemainHops <= 0 {
		return
	}
	if m.RemainHops = m.RemainHops - 1; m.RemainHops > maxAcceptableHopCount {
		m.RemainHops = maxAcceptableHopCount
	}
	if err := d.messageSwitch.forwardEncryptedEnvelopedMessage(m); nil != err {
		log.Printf("ERROR: cannot forward enveloped message (relay-index=%d): %v", d.relayIndex, err)
	}
}