package diagnosissocket

import (
	"log"
	"time"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

const (
	tickDuration            = time.Second * 10
	registerVerifyInterval  = time.Second * 5
	minimalTransmitInterval = time.Second * 5
)

func (d *DiagnosisSocketServer) ReadTrace(req *gen.ReadTraceRequest, stream gen.Qabalwrap1DiagnosisGRPC_ReadTraceServer) (err error) {
	instIdent := req.ClientInstanceIdent
	registerTimestamp := d.registConnectedTraceReader(instIdent)
	defer d.unregistConnectedTraceReader(instIdent)
	traceCh := d.diagnosisEmitter.GetTraceReadChannel()
	defer d.diagnosisEmitter.ReleaseTraceReadChannel()
	tick := time.NewTicker(tickDuration)
	defer tick.Stop()
	lastRegisterVerify := time.Now()
	lastTransmittion := time.Now()
	for {
		select {
		case traceRec := <-traceCh:
			if err = stream.Send(traceRec); nil != err {
				log.Printf("ERROR: (DiagnosisSocketServer:ReadTrace) cannot emit trace record: %v", err)
				return
			}
			lastTransmittion = time.Now()
		case <-tick.C:
			if time.Since(lastTransmittion) < minimalTransmitInterval {
				continue
			}
			heartbeatRec := &gen.TraceRecord{
				TraceType: int32(qabalwrap.EmptyTrace),
				EmitAt:    time.Now().Unix(),
			}
			if err = stream.Send(heartbeatRec); nil != err {
				log.Printf("ERROR: (DiagnosisSocketServer:ReadTrace) cannot emit heartbeat record: %v", err)
				return
			}
			lastTransmittion = time.Now()
		}
		if time.Since(lastRegisterVerify) >= registerVerifyInterval {
			if !d.verifyConnectedTraceReader(instIdent, registerTimestamp) {
				break
			}
		}
	}
	return
}
