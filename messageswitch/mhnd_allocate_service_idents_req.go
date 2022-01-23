package messageswitch

import (
	"github.com/google/uuid"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

func queueAllocateServiceIdentsRequest(spanEmitter *qabalwrap.TraceEmitter, s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	spanEmitter = spanEmitter.StartSpan("queue-allocate-service-idents-req")
	if !s.primarySwitch {
		spanEmitter.FinishSpan("failed: (queueAllocateServiceIdentsRequest) not primary switch: src=%d", m.SourceServiceIdent)
		return ErrNotSupportedOperation
	}
	var req qbw1grpcgen.AllocateServiceIdentsRequest
	if err = m.Unmarshal(&req); nil != err {
		spanEmitter.FinishSpan("failed: (queueAllocateServiceIdentsRequest) cannot unpack request: %v", err)
		return
	}
	var unassignedSrvRefs []*ServiceReference
	for _, ref := range req.ServiceIdents {
		uniqIdent, err := uuid.Parse(ref.UniqueIdent)
		if nil != err {
			spanEmitter.EventErrorf("(queueAllocateServiceIdentsRequest) cannot parse unique identifier: %v", err)
			continue
		}
		if ref.TextIdent == "" {
			spanEmitter.EventErrorf("(queueAllocateServiceIdentsRequest) text identifier must not empty: [%s]", ref.TextIdent)
			continue
		}
		srvRef := &ServiceReference{
			UniqueIdent: uniqIdent,
			SerialIdent: qabalwrap.UnknownServiceIdent,
			TextIdent:   ref.TextIdent,
		}
		if err := srvRef.PublicKey.UnmarshalBinary(ref.PublicKey); nil != err {
			spanEmitter.EventErrorf("(queueAllocateServiceIdentsRequest) cannot load public key [%s/%s]: %v", ref.UniqueIdent, ref.TextIdent, err)
			continue
		}
		unassignedSrvRefs = append(unassignedSrvRefs, srvRef)
	}
	if len(unassignedSrvRefs) == 0 {
		spanEmitter.FinishSpan("success: empty unassigned service reference")
		return
	}
	for _, srvRef := range unassignedSrvRefs {
		s.allocateServiceIdentsRequests <- &serviceReferenceRequest{
			ServiceRef:  srvRef,
			SpanEmitter: spanEmitter,
		}
		spanEmitter.EventInfof("(queueAllocateServiceIdentsRequest) push request [%s/%s] into queue.",
			srvRef.TextIdent, srvRef.UniqueIdent.String())
	}
	spanEmitter.FinishSpan("success")
	return
}

func handleAllocateServiceIdentsRequest(s *MessageSwitch, srvRefReq *serviceReferenceRequest) {
	spanEmitter := srvRefReq.SpanEmitter.StartSpan("hnd-allocate-service-ident")
	if !s.primarySwitch {
		spanEmitter.FinishSpan("failed: (handleAllocateServiceIdentsRequest) not primary switch: serviceRef=[%s/%s]",
			srvRefReq.ServiceRef.TextIdent, srvRefReq.ServiceRef.UniqueIdent.String())
		return
	}
	s.crossBar.addUnassignedServiceConnectByServiceReference(spanEmitter, srvRefReq.ServiceRef)
	s.crossBar.assignServiceSerialIdents(spanEmitter)
	spanEmitter.FinishSpan("success")
}
