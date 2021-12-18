package qabalwrap

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"
)

//go:generate stringer -type=TraceType

const DefaultTraceBufferSize = 16

// TraceType define type for trace type identifier.
type TraceType int32

// Identifier values of trace types.
const (
	EmptyTrace TraceType = iota
	TraceStart
	TraceFinish
	TraceSpanStart
	TraceSpanFinish
)

func newTraceRecord(traceEmitter *TraceEmitter, traceTypeIdent TraceType, messageText string) (record *qbw1diagrpcgen.TraceRecord) {
	record = &qbw1diagrpcgen.TraceRecord{
		TraceIdent:      traceEmitter.TraceIdent,
		SpanIdent:       traceEmitter.SpanIdent,
		ParentSpanIdent: traceEmitter.ParentSpanIdent,
		TraceType:       int32(traceTypeIdent),
		EmitAt:          time.Now().UnixNano(),
		MessageText:     messageText,
	}
	return
}

// DiagnosisEmitter wrap diagnosis data send and buffering.
type DiagnosisEmitter struct {
	serialPrefix  int32
	currentSerial uint32

	traceReaderCount int32
	traceRecordQueue chan *qbw1diagrpcgen.TraceRecord
}

func NewDiagnosisEmitter(serialPrefix int8, traceBufferSize int) (diag *DiagnosisEmitter) {
	if serialPrefix <= 0 {
		log.Printf("WARN: given serial prefix for diagnosis is not positive value: %d.", serialPrefix)
	}
	if traceBufferSize < 1 {
		traceBufferSize = DefaultTraceBufferSize
	}
	return &DiagnosisEmitter{
		serialPrefix:     (int32(serialPrefix) << 24) & 0x7F000000,
		traceRecordQueue: make(chan *qbw1diagrpcgen.TraceRecord, traceBufferSize),
	}
}

func (diag *DiagnosisEmitter) GetTraceReadChannel() (ch <-chan *qbw1diagrpcgen.TraceRecord) {
	atomic.AddInt32(&diag.traceReaderCount, 1)
	return diag.traceRecordQueue
}

func (diag *DiagnosisEmitter) ReleaseTraceReadChannel() {
	if remainReaderCount := atomic.AddInt32(&diag.traceReaderCount, -1); remainReaderCount < 0 {
		log.Printf("ERROR: trace reader count less than zero. [%d]", remainReaderCount)
	}
}

func (diag *DiagnosisEmitter) AllocateSerial() (result int32) {
	v := atomic.AddUint32(&diag.currentSerial, 1)
	result = diag.serialPrefix | int32(v&0x00FFFFFF)
	return
}

// enqueueTraceRecord is an internal method. Must invoke after checked if having current reader more than zero.
func (diag *DiagnosisEmitter) enqueueTraceRecord(traceEmitter *TraceEmitter, traceTypeIdent TraceType, messageText string) {
	record := newTraceRecord(traceEmitter, traceTypeIdent, messageText)
	select {
	case diag.traceRecordQueue <- record:
		return
	default:
		log.Printf("WARN: cannot queue trace message (Logf): full. TraceID=%08X, SpanID=%08X, ParentSpanID=%08X, TraceType=%s, EmitAt=%d, Message=[%s]",
			record.TraceIdent, record.SpanIdent, record.ParentSpanIdent, TraceType(record.TraceType).String(), record.EmitAt, record.MessageText)
	}
}

func (diag *DiagnosisEmitter) emitTraceRecordLogf(
	traceEmitter *TraceEmitter,
	traceTypeIdent TraceType,
	messageFmt string,
	a ...interface{}) {
	if currentReaderCnt := atomic.LoadInt32(&diag.traceReaderCount); currentReaderCnt <= 0 {
		return
	}
	var messageText string
	if len(a) == 0 {
		messageText = messageFmt
	} else {
		messageText = fmt.Sprintf(messageFmt, a...)
	}
	diag.enqueueTraceRecord(traceEmitter, traceTypeIdent, messageText)
}

func (diag *DiagnosisEmitter) StartTrace(traceMessageFmt string, a ...interface{}) (traceEmitter *TraceEmitter) {
	traceIdent := diag.AllocateSerial()
	traceEmitter = &TraceEmitter{
		diagnosisEmitter: diag,
		TraceIdent:       traceIdent,
		SpanIdent:        traceIdent,
		ParentSpanIdent:  traceIdent,
	}
	diag.emitTraceRecordLogf(traceEmitter, TraceStart, traceMessageFmt, a...)
	return
}

type TraceEmitter struct {
	diagnosisEmitter *DiagnosisEmitter

	TraceIdent      int32
	SpanIdent       int32
	ParentSpanIdent int32
}

func (emitter *TraceEmitter) FinishTrace(traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, TraceFinish, traceMessageFmt, a...)
}

func (emitter *TraceEmitter) StartSpan(traceMessageFmt string, a ...interface{}) (traceEmitter *TraceEmitter) {
	spanIdent := emitter.diagnosisEmitter.AllocateSerial()
	traceEmitter = &TraceEmitter{
		diagnosisEmitter: emitter.diagnosisEmitter,
		TraceIdent:       emitter.TraceIdent,
		SpanIdent:        spanIdent,
		ParentSpanIdent:  emitter.SpanIdent,
	}
	emitter.diagnosisEmitter.emitTraceRecordLogf(traceEmitter, TraceSpanStart, traceMessageFmt, a...)
	return
}

func (emitter *TraceEmitter) FinishSpan(traceMessageFmt string, a ...interface{}) (traceEmitter *TraceEmitter) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(traceEmitter, TraceSpanFinish, traceMessageFmt, a...)
	return
}

func (emitter *TraceEmitter) Logf(traceTypeIdent TraceType, traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, traceTypeIdent, traceMessageFmt, a...)
}
