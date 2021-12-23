package diagnosissocket

import (
	"context"
	"os"
	"time"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"
)

func (d *DiagnosisSocketServer) Ping(ctx context.Context, req *gen.PingRequest) (reply *gen.PingReply, err error) {
	reply = &gen.PingReply{
		Timestamp:    time.Now().Unix(),
		ProcessIdent: int32(os.Getpid()),
	}
	return
}
