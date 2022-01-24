package messageswitch

import (
	md5digest "github.com/go-marshaltemabu/go-md5digest"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type knownServiceIdentsNotifyHandler struct {
	s *MessageSwitch

	messageCache  *qabalwrap.EnvelopedMessage
	messageDigest md5digest.MD5Digest
}

func newKnownServiceIdentsNotifyHandler(spanEmitter *qabalwrap.TraceEmitter, s *MessageSwitch) (h knownServiceIdentsNotifyHandler, err error) {
	knownServiceIdentsMessage, knownServiceIdentsDigest, err := s.buildKnownServiceIdentsMessage(spanEmitter)
	if nil != err {
		spanEmitter.EventError("(newKnownServiceIdentsNotifyHandler) cannot build known service identifiers message: %v", err)
		return
	}
	h = knownServiceIdentsNotifyHandler{
		s:             s,
		messageCache:  knownServiceIdentsMessage,
		messageDigest: knownServiceIdentsDigest,
	}
	return
}

func (h *knownServiceIdentsNotifyHandler) handleAsPrimarySwitch(spanEmitter *qabalwrap.TraceEmitter, notice *knownServiceIdentsNotify) {
	localSwitchSerialIdent := h.s.localServiceRef.SerialIdent
	remoteSwitchSerialIdent := int(notice.knownServiceIdents.LocalSwitchSerialIdent)
	if remoteSwitchSerialIdent == 0 {
		remoteSwitchSerialIdent = qabalwrap.UnknownServiceIdent
	}
	relayIndex := notice.relayIndex
	for _, svrIdent := range notice.knownServiceIdents.ServiceIdents {
		conn := h.s.crossBar.getServiceConnectBySerial(int(svrIdent.SerialIdent))
		if conn == nil {
			spanEmitter.EventWarning("(knownServiceIdentsNotifyHandler::handleAsPrimarySwitch) cannot reach service connect (serial-ident=%d)", svrIdent.SerialIdent)
			continue
		}
		if svrIdent.TextIdent != conn.TextIdent {
			spanEmitter.EventWarning("(knownServiceIdentsNotifyHandler::handleAsPrimarySwitch) text identifier not match (serial-ident=%d): remote=[%s], local=[%s]",
				svrIdent.SerialIdent, svrIdent.TextIdent, conn.TextIdent)
			continue
		}
		if switchSerialIdent := svrIdent.LinkHopSwitchSerialIdent; (switchSerialIdent == int32(localSwitchSerialIdent)) || (switchSerialIdent == 0) || (switchSerialIdent == qabalwrap.UnknownServiceIdent) {
			continue
		}
		conn.updateRelayHopCount(spanEmitter, relayIndex, int(svrIdent.LinkHopCount), remoteSwitchSerialIdent)
	}
}

func (h *knownServiceIdentsNotifyHandler) handleAsOrdinarySwitch(spanEmitter *qabalwrap.TraceEmitter, notice *knownServiceIdentsNotify) {
	localSwitchSerialIdent := h.s.localServiceRef.SerialIdent
	remoteSwitchSerialIdent := int(notice.knownServiceIdents.LocalSwitchSerialIdent)
	if remoteSwitchSerialIdent == 0 {
		remoteSwitchSerialIdent = qabalwrap.UnknownServiceIdent
	}
	relayIndex := notice.relayIndex
	h.s.crossBar.expandServiceConnectsSlice(int(notice.knownServiceIdents.MaxSerialIdent))
	for _, svrIdent := range notice.knownServiceIdents.ServiceIdents {
		ref, err := newServiceReferenceFromQBW1RPCServiceIdent(svrIdent)
		if nil != err {
			spanEmitter.EventError("(knownServiceIdentsNotifyHandler::handleAsOrdinarySwitch) cannot generate service reference: %v",
				err)
			continue
		}
		conn := h.s.crossBar.getServiceConnectByServiceReference(spanEmitter, ref)
		if conn == nil {
			spanEmitter.EventWarning("(knownServiceIdentsNotifyHandler::handleAsPrimarySwitch) cannot reach service connect (serial-ident=%d)", svrIdent.SerialIdent)
			continue
		}
		if switchSerialIdent := svrIdent.LinkHopSwitchSerialIdent; (switchSerialIdent == int32(localSwitchSerialIdent)) || (switchSerialIdent == 0) || (switchSerialIdent == qabalwrap.UnknownServiceIdent) {
			continue
		}
		conn.updateRelayHopCount(spanEmitter, relayIndex, int(svrIdent.LinkHopCount), remoteSwitchSerialIdent)
	}
	h.s.crossBar.setServiceZeroSerialIdent(int(notice.knownServiceIdents.PrimarySerialIdent))
}

func (h *knownServiceIdentsNotifyHandler) handle(notice *knownServiceIdentsNotify) {
	spanEmitter := notice.spanEmitter.StartSpan("handle-known-service-ident-notify")
	if notice.knownServiceIdents == nil {
		spanEmitter.EventInfo("relay link lost: relay-index=%d", notice.relayIndex)
		h.s.crossBar.relayLinkLosted(spanEmitter, notice.relayIndex)
	} else if h.s.primarySwitch {
		h.handleAsPrimarySwitch(spanEmitter, notice)
	} else {
		h.handleAsOrdinarySwitch(spanEmitter, notice)
	}
	knownServiceIdentsMessage, knownServiceIdentsDigest, err := h.s.buildKnownServiceIdentsMessage(spanEmitter)
	if nil != err {
		spanEmitter.FinishSpanLogError("failed: (knownServiceIdentsNotifyHandler::handle) cannot build known service identifiers message: %v", err)
		return
	}
	if knownServiceIdentsDigest == h.messageDigest {
		h.s.nonblockingRelayPeerMessage(spanEmitter, notice.relayIndex, h.messageCache)
		spanEmitter.FinishSpan("success: use cache")
	} else {
		h.messageCache = knownServiceIdentsMessage
		h.messageDigest = knownServiceIdentsDigest
		h.s.nonblockingRelayPeerBroadcast(spanEmitter, h.messageCache)
		spanEmitter.FinishSpan("success: changed")
	}
}

func (h *knownServiceIdentsNotifyHandler) emitCachedKnownServiceIdents(spanEmitter *qabalwrap.TraceEmitter, relayIndex int) {
	spanEmitter = spanEmitter.StartSpan("emit-cache-for-known-service-ident-notify")
	defer spanEmitter.FinishSpan("success")
	h.s.nonblockingRelayPeerMessage(spanEmitter, relayIndex, h.messageCache)
}

func (h *knownServiceIdentsNotifyHandler) checkChanges(spanEmitter *qabalwrap.TraceEmitter) {
	spanEmitter = spanEmitter.StartSpan("known-service-ident-notify-check-change")
	knownServiceIdentsMessage, knownServiceIdentsDigest, err := h.s.buildKnownServiceIdentsMessage(spanEmitter)
	if nil != err {
		spanEmitter.FinishSpanLogError("failed: (knownServiceIdentsNotifyHandler::checkChanges) cannot build known service identifiers message: %v", err)
		return
	}
	if knownServiceIdentsDigest == h.messageDigest {
		spanEmitter.FinishSpan("success: (knownServiceIdentsNotifyHandler::checkChanges) no change.")
		return
	}
	spanEmitter.EventInfo("(knownServiceIdentsNotifyHandler::checkChanges) changed.")
	h.messageCache = knownServiceIdentsMessage
	h.messageDigest = knownServiceIdentsDigest
	h.s.nonblockingRelayPeerBroadcast(spanEmitter, h.messageCache)
	spanEmitter.FinishSpan("success")
}
