package exporttrace

import (
	"context"
	"flag"
	"log"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"

	instanceident "github.com/nangantata/go-instanceident"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

const (
	runnerActionName    = "qabalwrap-diag"
	runnerActionVersion = "0.0.1"
)

type Runner struct {
	otlpEndpoint    string
	sessionIdentRef int64
	sessionIdent    uint32

	stagedSpans map[int32]*spanInstance
}

// Name return command name.
func (cr *Runner) Name() string {
	return "exporttrace"
}

// SetFlags init given flag set.
func (cr *Runner) SetFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(&cr.otlpEndpoint, "endpoint", "localhost:4317", "endpoint of OTLP trace collector")
	flagSet.Int64Var(&cr.sessionIdentRef, "session", 0, "export session identifier")
}

// CheckFlags will be invoke after flagSet.Parse() called.
// Return non-nil error if any unexpect flag values is given.
func (cr *Runner) CheckFlags() (err error) {
	if cr.sessionIdentRef == 0 {
		cr.sessionIdent = uint32(time.Now().UnixNano()) & 0x7FFFFFFF
	} else {
		cr.sessionIdent = uint32(cr.sessionIdentRef) & 0x7FFFFFFF
	}
	cr.stagedSpans = make(map[int32]*spanInstance)
	return
}

// Run perform command operation.
func (cr *Runner) Run(ctx context.Context, client gen.Qabalwrap1DiagnosisGRPCClient) (err error) {
	exporter, err := otlptracegrpc.New(ctx, /* for open connection */
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(cr.otlpEndpoint))
	if err != nil {
		log.Printf("ERROR: (exportTraceRunner::Run) cannot create trace exporter: %v", err)
		return
	}
	defer exporter.Shutdown(ctx)
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
	log.Printf("INFO: export trace as [session: %d (%08X)]", cr.sessionIdent, cr.sessionIdent)
	traceRec, err := traceReader.Recv()
	exportBatch := make([]*spanInstance, 0, 16)
	lastExportAt := time.Now()
	for nil == err {
		switch traceType := qabalwrap.TraceType(traceRec.TraceType); traceType {
		case qabalwrap.EmptyTrace:
			log.Printf("INFO: trace heartbeat: emit-at=%d", traceRec.EmitAt)
		case qabalwrap.TraceStart:
			fallthrough
		case qabalwrap.TraceSpanStart:
			if ref := cr.stagedSpans[traceRec.SpanIdent]; ref == nil {
				spanInst := newSpanInstance(cr.sessionIdent, traceRec)
				cr.stagedSpans[traceRec.SpanIdent] = spanInst
			} else {
				log.Printf("WARN: duplicated span start: trace-ident=%X, span-ident=%X", traceRec.TraceIdent, traceRec.SpanIdent)
			}
		case qabalwrap.TraceFinish:
			fallthrough
		case qabalwrap.TraceSpanFinish:
			if ref := cr.stagedSpans[traceRec.SpanIdent]; ref != nil {
				ref.finishSpan(traceRec)
				exportBatch = append(exportBatch, ref)
				delete(cr.stagedSpans, traceRec.SpanIdent)
			} else {
				log.Printf("WARN: (finish-span) cannot reach span: trace-ident=%X, span-ident=%X", traceRec.TraceIdent, traceRec.SpanIdent)
			}
		case qabalwrap.EventError:
			if ref := cr.stagedSpans[traceRec.SpanIdent]; ref != nil {
				ref.eventError(traceRec)
			} else {
				log.Printf("WARN: (event-error) cannot reach span: trace-ident=%X, span-ident=%X: %s", traceRec.TraceIdent, traceRec.SpanIdent, traceRec.MessageText)
			}
		case qabalwrap.EventWarning:
			if ref := cr.stagedSpans[traceRec.SpanIdent]; ref != nil {
				ref.eventWarning(traceRec)
			} else {
				log.Printf("WARN: (event-warning) cannot reach span: trace-ident=%X, span-ident=%X: %s", traceRec.TraceIdent, traceRec.SpanIdent, traceRec.MessageText)
			}
		case qabalwrap.EventInfo:
			if ref := cr.stagedSpans[traceRec.SpanIdent]; ref != nil {
				ref.eventInfo(traceRec)
			} else {
				log.Printf("WARN: (event-info) cannot reach span: trace-ident=%X, span-ident=%X: %s", traceRec.TraceIdent, traceRec.SpanIdent, traceRec.MessageText)
			}
		case qabalwrap.LinkedTrace:
			if ref := cr.stagedSpans[traceRec.SpanIdent]; ref != nil {
				ref.appendLinkSpans(cr.sessionIdent, traceRec)
			} else {
				log.Printf("WARN: (linked-trace) cannot reach span: trace-ident=%X, span-ident=%X", traceRec.TraceIdent, traceRec.SpanIdent)
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
		if (len(exportBatch) > 0) && (time.Since(lastExportAt) > time.Second*10) {
			lastExportAt = time.Now()
			exportSpans := makeReadOnlySpans(exportBatch...)
			exportBatch = make([]*spanInstance, 0, 16)
			if err = exporter.ExportSpans(ctx, exportSpans); nil != err {
				log.Printf("ERROR: cannot export span batch: %v", err)
			}
		}
		traceRec, err = traceReader.Recv()
	}
	return
}
