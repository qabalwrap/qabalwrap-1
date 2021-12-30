package main

import (
	"context"
	"flag"
	"log"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"
)

type pingRunner struct{}

// Name return command name.
func (cr *pingRunner) Name() string {
	return "ping"
}

// SetFlags init given flag set.
func (cr *pingRunner) SetFlags(flagSet *flag.FlagSet) {}

// CheckFlags will be invoke after flagSet.Parse() called.
// Return non-nil error if any unexpect flag values is given.
func (cr *pingRunner) CheckFlags() (err error) {
	return
}

// Run perform command operation.
func (cr *pingRunner) Run(ctx context.Context, client gen.Qabalwrap1DiagnosisGRPCClient) (err error) {
	reply, err := client.Ping(ctx, &gen.PingRequest{})
	if nil != err {
		return
	}
	log.Printf("INFO: ping result: time-stamp=%d, process-ident=%d", reply.Timestamp, reply.ProcessIdent)
	return
}
