package readtrace

import (
	"context"
	"flag"
	"log"

	instanceident "github.com/nangantata/go-instanceident"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type Runner struct{}

// Name return command name.
func (cr *Runner) Name() string {
	return "readtrace"
}

// SetFlags init given flag set.
func (cr *Runner) SetFlags(flagSet *flag.FlagSet) {}

// CheckFlags will be invoke after flagSet.Parse() called.
// Return non-nil error if any unexpect flag values is given.
func (cr *Runner) CheckFlags() (err error) {
	return
}

// Run perform command operation.
func (cr *Runner) Run(ctx context.Context, client gen.Qabalwrap1DiagnosisGRPCClient) (err error) {
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
		switch traceType := qabalwrap.TraceType(traceRec.TraceType); traceType {
		case qabalwrap.EmptyTrace:
			log.Printf("INFO: trace heartbeat: emit-at=%d", traceRec.EmitAt)
		case qabalwrap.LinkedTrace:
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
		traceRec, err = traceReader.Recv()
	}
	return
}
