package main

import (
	"context"
	"flag"
	"log"

	instanceident "github.com/nangantata/go-instanceident"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type readTraceRunner struct{}

// Name return command name.
func (cr *readTraceRunner) Name() string {
	return "readtrace"
}

// SetFlags init given flag set.
func (cr *readTraceRunner) SetFlags(flagSet *flag.FlagSet) {}

// CheckFlags will be invoke after flagSet.Parse() called.
// Return non-nil error if any unexpect flag values is given.
func (cr *readTraceRunner) CheckFlags() (err error) {
	return
}

// Run perform command operation.
func (cr *readTraceRunner) Run(ctx context.Context, client gen.Qabalwrap1DiagnosisGRPCClient) (err error) {
	instIdent, err := instanceident.ProcessDerivedStringIdentity()
	if nil != err {
		return
	}
	traceReader, err := client.ReadTrace(ctx, &gen.ReadTraceRequest{
		ClientInstanceIdent: instIdent,
	})
	if nil != err {
		log.Printf("ERROR: cannot start trace read: %v", err)
		return
	}
	log.Printf("INFO: start reading trace as [%s]", instIdent)
	traceRec, err := traceReader.Recv()
	for nil == err {
		traceType := qabalwrap.TraceType(traceRec.TraceType)
		if traceType == qabalwrap.EmptyTrace {
			log.Printf("INFO: trace heartbeat: emit-at=%d", traceRec.EmitAt)
		} else {
			switch traceRec.TraceType {
			case int32(qabalwrap.LinkedTrace):
				log.Printf("INFO: trace link: emit-at=%d, trace-type=%d, trace-ident=%X, span-ident=%X(parent=%X):",
					traceRec.EmitAt,
					traceRec.TraceType,
					traceRec.TraceIdent,
					traceRec.SpanIdent,
					traceRec.ParentSpanIdent)
				for lnkIdx, lnkRef := range traceRec.LinkedSpans {
					log.Printf("INFO: -- %03d - trace-ident=%X, span-ident=%X", lnkIdx, lnkRef.TraceIdent, lnkRef.SpanIdent)
				}
			default:
				log.Printf("INFO: trace record: emit-at=%d, trace-type=%d, trace-ident=%X, span-ident=%X(parent=%X) [%s]",
					traceRec.EmitAt,
					traceRec.TraceType,
					traceRec.TraceIdent,
					traceRec.SpanIdent,
					traceRec.ParentSpanIdent,
					traceRec.MessageText)
			}
		}
		traceRec, err = traceReader.Recv()
	}
	return
}
