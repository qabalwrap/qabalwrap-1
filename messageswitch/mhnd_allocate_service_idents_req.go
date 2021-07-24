package messageswitch

import (
	"log"

	"github.com/google/uuid"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

func queueAllocateServiceIdentsRequest(s *MessageSwitch, m *qabalwrap.EnvelopedMessage) (err error) {
	if !s.primarySwitch {
		log.Printf("ERROR: (queueAllocateServiceIdentsRequest) not primary switch: src=%d", m.SourceServiceIdent)
		return ErrNotSupportedOperation
	}
	var req qbw1grpcgen.AllocateServiceIdentsRequest
	if err = m.Unmarshal(&req); nil != err {
		log.Printf("ERROR: (queueAllocateServiceIdentsRequest) cannot unpack request: %v", err)
		return
	}
	var unassignedSrvRefs []*ServiceReference
	for _, ref := range req.ServiceIdents {
		uniqIdent, err := uuid.Parse(ref.UniqueIdent)
		if nil != err {
			log.Printf("ERROR: (queueAllocateServiceIdentsRequest) cannot parse unique identifier: %v", err)
			continue
		}
		if ref.TextIdent == "" {
			log.Printf("ERROR: (queueAllocateServiceIdentsRequest) text identifier must not empty: [%s]", ref.TextIdent)
			continue
		}
		srvRef := &ServiceReference{
			UniqueIdent: uniqIdent,
			SerialIdent: qabalwrap.UnknownServiceIdent,
			TextIdent:   ref.TextIdent,
		}
		if err := srvRef.PublicKey.UnmarshalBinary(ref.PublicKey); nil != err {
			log.Printf("ERROR: (queueAllocateServiceIdentsRequest) cannot load public key [%s/%s]: %v", ref.UniqueIdent, ref.TextIdent, err)
			continue
		}
		unassignedSrvRefs = append(unassignedSrvRefs, srvRef)
	}
	if len(unassignedSrvRefs) == 0 {
		return
	}
	for _, srvRef := range unassignedSrvRefs {
		s.allocateServiceIdentsRequests <- srvRef
		log.Printf("INFO: (queueAllocateServiceIdentsRequest) push request [%s/%s] into queue.",
			srvRef.TextIdent, srvRef.UniqueIdent.String())
	}
	return
}

func handleAllocateServiceIdentsRequest(s *MessageSwitch, srvRef *ServiceReference) {
	if !s.primarySwitch {
		log.Printf("ERROR: (handleAllocateServiceIdentsRequest) not primary switch: serviceRef=[%s/%s]", srvRef.TextIdent, srvRef.UniqueIdent.String())
		return
	}
	s.crossBar.addUnassignedServiceConnectByServiceReference(srvRef)
	s.crossBar.assignServiceSerialIdents()
}
