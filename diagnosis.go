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
	eventTagBegin
	EventInfo
	EventWarning
	EventError
	eventTagEnd
	LinkedTrace
)

var eventTagText = [...]string{"DEBUG:", "INFO:", "WARN:", "ERROR:"}

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

func newLinkedTraceRecordWithBaggagedMessages(traceEmitter *TraceEmitter, linkedMessages []*BaggagedMessage) (record *qbw1diagrpcgen.TraceRecord) {
	linkedSpans := make([]*qbw1diagrpcgen.SpanIdent, 0, len(linkedMessages))
	for _, bagMsg := range linkedMessages {
		linkedSpans = append(linkedSpans, &qbw1diagrpcgen.SpanIdent{
			TraceIdent: bagMsg.TraceIdent,
			SpanIdent:  bagMsg.SpanIdent,
		})
	}
	record = &qbw1diagrpcgen.TraceRecord{
		TraceIdent:      traceEmitter.TraceIdent,
		SpanIdent:       traceEmitter.SpanIdent,
		ParentSpanIdent: traceEmitter.ParentSpanIdent,
		TraceType:       int32(LinkedTrace),
		EmitAt:          time.Now().UnixNano(),
		LinkedSpans:     linkedSpans,
	}
	return
}

func newLinkedTraceRecordWithSpanIdents(traceEmitter *TraceEmitter, linkedSpanIdents []*qbw1diagrpcgen.SpanIdent) (record *qbw1diagrpcgen.TraceRecord) {
	record = &qbw1diagrpcgen.TraceRecord{
		TraceIdent:      traceEmitter.TraceIdent,
		SpanIdent:       traceEmitter.SpanIdent,
		ParentSpanIdent: traceEmitter.ParentSpanIdent,
		TraceType:       int32(LinkedTrace),
		EmitAt:          time.Now().UnixNano(),
		LinkedSpans:     linkedSpanIdents,
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

func (diag *DiagnosisEmitter) emitTraceRecordErrLogf(
	traceEmitter *TraceEmitter,
	traceTypeIdent TraceType,
	messageFmt string,
	a ...interface{}) {
	var messageText string
	if len(a) == 0 {
		messageText = messageFmt
	} else {
		messageText = fmt.Sprintf(messageFmt, a...)
	}
	log.Print("ERROR:", messageText)
	if currentReaderCnt := atomic.LoadInt32(&diag.traceReaderCount); currentReaderCnt <= 0 {
		return
	}
	diag.enqueueTraceRecord(traceEmitter, traceTypeIdent, messageText)
}

func (diag *DiagnosisEmitter) emitLinkedTraceRecordWithBaggagedMessages(
	traceEmitter *TraceEmitter, linkedMessages []*BaggagedMessage) {
	if currentReaderCnt := atomic.LoadInt32(&diag.traceReaderCount); currentReaderCnt <= 0 {
		return
	}
	record := newLinkedTraceRecordWithBaggagedMessages(traceEmitter, linkedMessages)
	select {
	case diag.traceRecordQueue <- record:
		return
	default:
		log.Printf("WARN: cannot queue linked (via baggage messages) trace message: full. TraceID=%08X, SpanID=%08X, ParentSpanID=%08X, TraceType=%s, EmitAt=%d, LinkedSpanCount=[%d]",
			record.TraceIdent, record.SpanIdent, record.ParentSpanIdent, TraceType(record.TraceType).String(), record.EmitAt, len(record.LinkedSpans))
	}
}

func (diag *DiagnosisEmitter) emitLinkedTraceRecordWithSpanIdents(
	traceEmitter *TraceEmitter, linkedSpanIdents []*qbw1diagrpcgen.SpanIdent) {
	if currentReaderCnt := atomic.LoadInt32(&diag.traceReaderCount); currentReaderCnt <= 0 {
		return
	}
	record := newLinkedTraceRecordWithSpanIdents(traceEmitter, linkedSpanIdents)
	select {
	case diag.traceRecordQueue <- record:
		return
	default:
		log.Printf("WARN: cannot queue linked (via span idents) trace message: full. TraceID=%08X, SpanID=%08X, ParentSpanID=%08X, TraceType=%s, EmitAt=%d, LinkedSpanCount=[%d]",
			record.TraceIdent, record.SpanIdent, record.ParentSpanIdent, TraceType(record.TraceType).String(), record.EmitAt, len(record.LinkedSpans))
	}
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

func (diag *DiagnosisEmitter) StartSpanFromRemoteTrace(remoteTraceIdent int32, remoteSpanIdent int32, traceMessageFmt string, a ...interface{}) (traceEmitter *TraceEmitter) {
	spanIdent := diag.AllocateSerial()
	traceEmitter = &TraceEmitter{
		diagnosisEmitter: diag,
		TraceIdent:       remoteTraceIdent,
		SpanIdent:        spanIdent,
		ParentSpanIdent:  remoteSpanIdent,
	}
	diag.emitTraceRecordLogf(traceEmitter, TraceSpanStart, traceMessageFmt, a...)
	return
}

type TraceEmitter struct {
	diagnosisEmitter *DiagnosisEmitter

	TraceIdent      int32
	SpanIdent       int32
	ParentSpanIdent int32
}

func (emitter *TraceEmitter) TraceSpanIdent() (traceSpanIdent *qbw1diagrpcgen.SpanIdent) {
	traceSpanIdent = &qbw1diagrpcgen.SpanIdent{
		TraceIdent: emitter.TraceIdent,
		SpanIdent:  emitter.SpanIdent,
	}
	return
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

func (emitter *TraceEmitter) FinishSpan(traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, TraceSpanFinish, traceMessageFmt, a...)
}

func (emitter *TraceEmitter) FinishSpanLogError(traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordErrLogf(emitter, TraceSpanFinish, traceMessageFmt, a...)
}

func (emitter *TraceEmitter) FinishSpanFailedErr(err error) {
	messageText := "failed: " + err.Error()
	emitter.diagnosisEmitter.emitTraceRecordErrLogf(emitter, TraceSpanFinish, messageText)
}

func (emitter *TraceEmitter) FinishSpanCheckErr(err error) {
	if nil != err {
		messageText := "failed: " + err.Error()
		emitter.diagnosisEmitter.emitTraceRecordErrLogf(emitter, TraceSpanFinish, messageText)
		return
	}
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, TraceSpanFinish, "success")
}

func (emitter *TraceEmitter) FinishSpanCheckBool(isSuccess bool) {
	var traceMessage string
	if isSuccess {
		traceMessage = "success"
	} else {
		traceMessage = "failed"
	}
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, TraceSpanFinish, traceMessage)
}

func (emitter *TraceEmitter) Logf(traceTypeIdent TraceType, traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, traceTypeIdent, traceMessageFmt, a...)
}

func (emitter *TraceEmitter) EventInfo(traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, EventInfo, traceMessageFmt, a...)
}

func (emitter *TraceEmitter) EventWarning(traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, EventWarning, traceMessageFmt, a...)
}

func (emitter *TraceEmitter) EventError(traceMessageFmt string, a ...interface{}) {
	emitter.diagnosisEmitter.emitTraceRecordLogf(emitter, EventError, traceMessageFmt, a...)
}

func (emitter *TraceEmitter) LinkBaggagedMessages(linkedMessages []*BaggagedMessage) {
	emitter.diagnosisEmitter.emitLinkedTraceRecordWithBaggagedMessages(emitter, linkedMessages)
}

func (emitter *TraceEmitter) LinkSpanIdents(linkedSpanIdents []*qbw1diagrpcgen.SpanIdent) {
	emitter.diagnosisEmitter.emitLinkedTraceRecordWithSpanIdents(emitter, linkedSpanIdents)
}
