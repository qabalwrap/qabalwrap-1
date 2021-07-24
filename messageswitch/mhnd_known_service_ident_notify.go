package messageswitch

import (
	"log"

	md5digest "github.com/go-marshaltemabu/go-md5digest"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type knownServiceIdentsNotifyHandler struct {
	s *MessageSwitch

	messageCache  *qabalwrap.EnvelopedMessage
	messageDigest md5digest.MD5Digest
}

func newKnownServiceIdentsNotifyHandler(s *MessageSwitch) (h knownServiceIdentsNotifyHandler, err error) {
	knownServiceIdentsMessage, knownServiceIdentsDigest, err := s.buildKnownServiceIdentsMessage()
	if nil != err {
		log.Printf("ERROR: (newKnownServiceIdentsNotifyHandler) cannot build known service identifiers message: %v", err)
		return
	}
	h = knownServiceIdentsNotifyHandler{
		s:             s,
		messageCache:  knownServiceIdentsMessage,
		messageDigest: knownServiceIdentsDigest,
	}
	return
}

func (h *knownServiceIdentsNotifyHandler) handleAsPrimarySwitch(notice *knownServiceIdentsNotify) {
	relayIndex := notice.relayIndex
	for _, svrIdent := range notice.knownServiceIdents.ServiceIdents {
		conn := h.s.crossBar.getServiceConnectBySerial(int(svrIdent.SerialIdent))
		if conn == nil {
			log.Printf("WARN: (knownServiceIdentsNotifyHandler::handleAsPrimarySwitch) cannot reach service connect (serial-ident=%d)", svrIdent.SerialIdent)
			continue
		}
		if svrIdent.TextIdent != conn.TextIdent {
			log.Printf("WARN: (knownServiceIdentsNotifyHandler::handleAsPrimarySwitch) text identifier not match (serial-ident=%d): remote=[%s], local=[%s]",
				svrIdent.SerialIdent, svrIdent.TextIdent, conn.TextIdent)
			continue
		}
		conn.updateRelayHopCount(relayIndex, int(svrIdent.LinkHopCount))
	}
}

func (h *knownServiceIdentsNotifyHandler) handleAsOrdinarySwitch(notice *knownServiceIdentsNotify) {
	relayIndex := notice.relayIndex
	h.s.crossBar.expandServiceConnectsSlice(int(notice.knownServiceIdents.MaxSerialIdent))
	for _, svrIdent := range notice.knownServiceIdents.ServiceIdents {
		ref, err := newServiceReferenceFromQBW1RPCServiceIdent(svrIdent)
		if nil != err {
			log.Printf("ERROR: (knownServiceIdentsNotifyHandler::handleAsOrdinarySwitch) cannot generate service reference: %v",
				err)
			continue
		}
		conn := h.s.crossBar.getServiceConnectByServiceReference(ref)
		if conn == nil {
			log.Printf("WARN: (knownServiceIdentsNotifyHandler::handleAsPrimarySwitch) cannot reach service connect (serial-ident=%d)", svrIdent.SerialIdent)
			continue
		}
		conn.updateRelayHopCount(relayIndex, int(svrIdent.LinkHopCount))
	}
}

func (h *knownServiceIdentsNotifyHandler) handle(notice *knownServiceIdentsNotify) {
	if notice.knownServiceIdents == nil {
		h.s.crossBar.relayLinkLosted(notice.relayIndex)
	} else if h.s.primarySwitch {
		h.handleAsPrimarySwitch(notice)
	} else {
		h.handleAsOrdinarySwitch(notice)
	}
	knownServiceIdentsMessage, knownServiceIdentsDigest, err := h.s.buildKnownServiceIdentsMessage()
	if nil != err {
		log.Printf("ERROR: (knownServiceIdentsNotifyHandler::handle) cannot build known service identifiers message: %v", err)
		return
	}
	if knownServiceIdentsDigest == h.messageDigest {
		h.s.nonblockingRelayPeerMessage(notice.relayIndex, h.messageCache)
	} else {
		h.messageCache = knownServiceIdentsMessage
		h.messageDigest = knownServiceIdentsDigest
		h.s.nonblockingRelayPeerBroadcast(h.messageCache)
	}
}

func (h *knownServiceIdentsNotifyHandler) checkChanges() {
	knownServiceIdentsMessage, knownServiceIdentsDigest, err := h.s.buildKnownServiceIdentsMessage()
	if nil != err {
		log.Printf("ERROR: (knownServiceIdentsNotifyHandler::check) cannot build known service identifiers message: %v", err)
		return
	}
	if knownServiceIdentsDigest == h.messageDigest {
		return
	}
	h.messageCache = knownServiceIdentsMessage
	h.messageDigest = knownServiceIdentsDigest
	h.s.nonblockingRelayPeerBroadcast(h.messageCache)
}
