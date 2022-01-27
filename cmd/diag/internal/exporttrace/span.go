package exporttrace

import (
	"encoding/binary"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"
)

var instrumentLibrary = instrumentation.Library{
	Name:      runnerActionName,
	Version:   runnerActionVersion,
	SchemaURL: semconv.SchemaURL,
}

var defaultServiceResourceAttr = resource.NewWithAttributes(
	semconv.SchemaURL,
	semconv.ServiceNameKey.String("qabalwrap-empty-service-name"),
	semconv.ServiceVersionKey.String(runnerActionVersion),
)

var serviceNameAttrMap = make(map[string]*resource.Resource)

func findServiceNameResource(serviceName string) *resource.Resource {
	if serviceName == "" {
		return defaultServiceResourceAttr
	}
	srvRes := serviceNameAttrMap[serviceName]
	if srvRes == nil {
		srvRes = resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		)
		serviceNameAttrMap[serviceName] = srvRes
	}
	return srvRes
}

func makeSpanContext(traceIdent, spanIdent uint64) (result trace.SpanContext) {
	resultCfg := trace.SpanContextConfig{
		Remote: false,
	}
	binary.BigEndian.PutUint64(resultCfg.TraceID[8:], traceIdent)
	binary.BigEndian.PutUint64(resultCfg.SpanID[:], spanIdent)
	result = trace.NewSpanContext(resultCfg)
	return
}

type traceSpanIdentifier struct {
	TraceIdent uint64
	SpanIdent  uint64
}

func addSessionIdentToTraceSpanIdent(sessionIdent uint32, traceIdent, spanIdent int32) (sessionTraceIdent, sessionSpanIdent uint64) {
	sessionTraceIdent = (uint64(traceIdent) << 32) | uint64(sessionIdent)
	sessionSpanIdent = (uint64(sessionIdent) << 32) | uint64(spanIdent)
	return
}

type spanInstance struct {
	sdktrace.ReadOnlySpan

	TraceIdent      uint64
	SpanIdent       uint64
	ParentSpanIdent uint64
	ServiceName     string
	TitleText       string
	MessageText     string
	StartAt         time.Time
	EndAt           time.Time
	LinkedSpans     []traceSpanIdentifier

	loggedEvents []sdktrace.Event

	statusSuccess     bool
	statusFailed      bool
	statusDescription string
}

func newSpanInstance(sessionIdent uint32, traceRec *gen.TraceRecord) (s *spanInstance) {
	traceIdent, spanIdent := addSessionIdentToTraceSpanIdent(sessionIdent, traceRec.TraceIdent, traceRec.SpanIdent)
	var parentSpanIdent uint64
	if traceRec.ParentSpanIdent != traceRec.SpanIdent {
		parentSpanIdent = (uint64(sessionIdent) << 32) | uint64(traceRec.ParentSpanIdent)
	}
	s = &spanInstance{
		TraceIdent:      traceIdent,
		SpanIdent:       spanIdent,
		ParentSpanIdent: parentSpanIdent,
		ServiceName:     traceRec.ServiceName,
		TitleText:       traceRec.OperationName,
		MessageText:     traceRec.MessageText,
		StartAt:         time.Unix(0, traceRec.EmitAt),
	}
	return
}

func (s *spanInstance) finishSpan(traceRec *gen.TraceRecord) {
	if traceRec.IsSuccess {
		s.statusSuccess = true
	} else {
		s.statusFailed = true
	}
	s.statusDescription = traceRec.MessageText
	s.EndAt = time.Unix(0, traceRec.EmitAt)
}

func (s *spanInstance) addLoggedEvent(eventName, messageText string, emitAt int64) {
	evt := sdktrace.Event{
		Name: eventName,
		Attributes: []attribute.KeyValue{
			attribute.Key("log.message").String(messageText),
		},
		Time: time.Unix(0, emitAt),
	}
	s.loggedEvents = append(s.loggedEvents, evt)
}

func (s *spanInstance) eventError(traceRec *gen.TraceRecord) {
	evt := sdktrace.Event{
		Name: semconv.ExceptionEventName,
		Attributes: []attribute.KeyValue{
			semconv.ExceptionMessageKey.String(traceRec.MessageText),
		},
		Time: time.Unix(0, traceRec.EmitAt),
	}
	s.loggedEvents = append(s.loggedEvents, evt)
}

func (s *spanInstance) eventWarning(traceRec *gen.TraceRecord) {
	s.addLoggedEvent("warn", traceRec.MessageText, traceRec.EmitAt)
}

func (s *spanInstance) eventInfo(traceRec *gen.TraceRecord) {
	s.addLoggedEvent("info", traceRec.MessageText, traceRec.EmitAt)
}

func (s *spanInstance) appendLinkSpans(sessionIdent uint32, traceRec *gen.TraceRecord) {
	l := len(s.LinkedSpans)
	if l == 0 {
		return
	}
	linkedSpans := make([]traceSpanIdentifier, 0, len(traceRec.LinkedSpans))
	for _, lnkSpan := range traceRec.LinkedSpans {
		lnkTraceIdent, lnkSpanIdent := addSessionIdentToTraceSpanIdent(sessionIdent, lnkSpan.TraceIdent, lnkSpan.SpanIdent)
		linkedSpans = append(linkedSpans, traceSpanIdentifier{
			TraceIdent: lnkTraceIdent,
			SpanIdent:  lnkSpanIdent,
		})
	}
	if l > 0 {
		s.LinkedSpans = append(s.LinkedSpans, linkedSpans...)
	} else {
		s.LinkedSpans = linkedSpans
	}
}

// Name returns the name of the span.
func (s *spanInstance) Name() string {
	return s.TitleText
}

// SpanContext returns the unique SpanContext that identifies the span.
func (s *spanInstance) SpanContext() trace.SpanContext {
	return makeSpanContext(s.TraceIdent, s.SpanIdent)
}

// Parent returns the unique SpanContext that identifies the parent of the
// span if one exists. If the span has no parent the returned SpanContext
// will be invalid.
func (s *spanInstance) Parent() trace.SpanContext {
	if s.ParentSpanIdent == 0 {
		return trace.SpanContext{}
	}
	return makeSpanContext(s.TraceIdent, s.ParentSpanIdent)
}

// SpanKind returns the role the span plays in a Trace.
func (s *spanInstance) SpanKind() trace.SpanKind {
	return trace.SpanKindUnspecified
}

// StartTime returns the time the span started recording.
func (s *spanInstance) StartTime() time.Time {
	return s.StartAt
}

// EndTime returns the time the span stopped recording. It will be zero if
// the span has not ended.
func (s *spanInstance) EndTime() time.Time {
	return s.EndAt
}

// Attributes returns the defining attributes of the span.
func (s *spanInstance) Attributes() []attribute.KeyValue {
	var attrs []attribute.KeyValue
	if s.MessageText != "" {
		attrs = append(attrs, attribute.Key("start.message").String(s.MessageText))
	}
	if s.statusDescription != "" {
		attrs = append(attrs, attribute.Key("finishing.message").String(s.statusDescription))
	}
	return attrs
}

// Links returns all the links the span has to other spans.
func (s *spanInstance) Links() []sdktrace.Link {
	if len(s.LinkedSpans) == 0 {
		return nil
	}
	result := make([]sdktrace.Link, len(s.LinkedSpans))
	for idx, linkedSpanInst := range s.LinkedSpans {
		result[idx] = sdktrace.Link{
			SpanContext: makeSpanContext(linkedSpanInst.TraceIdent, linkedSpanInst.SpanIdent),
		}
	}
	return result
}

// Events returns all the events that occurred within in the spans
// lifetime.
func (s *spanInstance) Events() []sdktrace.Event {
	return s.loggedEvents
}

// Status returns the spans status.
func (s *spanInstance) Status() sdktrace.Status {
	if s.statusFailed {
		return sdktrace.Status{
			Code:        codes.Error,
			Description: s.statusDescription,
		}
	} else if s.statusSuccess {
		return sdktrace.Status{
			Code: codes.Ok,
		}
	}
	return sdktrace.Status{}
}

// InstrumentationLibrary returns information about the instrumentation
// library that created the span.
func (s *spanInstance) InstrumentationLibrary() instrumentation.Library {
	return instrumentLibrary
}

// Resource returns information about the entity that produced the span.
func (s *spanInstance) Resource() *resource.Resource {
	return findServiceNameResource(s.ServiceName)
}

// DroppedAttributes returns the number of attributes dropped by the span
// due to limits being reached.
func (s *spanInstance) DroppedAttributes() int {
	return 0
}

// DroppedLinks returns the number of links dropped by the span due to
// limits being reached.
func (s *spanInstance) DroppedLinks() int {
	return 0
}

// DroppedEvents returns the number of events dropped by the span due to
// limits being reached.
func (s *spanInstance) DroppedEvents() int {
	return 0
}

// ChildSpanCount returns the count of spans that consider the span a
// direct parent.
func (s *spanInstance) ChildSpanCount() int {
	return 0
}

func makeReadOnlySpans(spanInsts ...*spanInstance) (spanSlice []sdktrace.ReadOnlySpan) {
	spanSlice = make([]sdktrace.ReadOnlySpan, 0, len(spanInsts))
	for _, inst := range spanInsts {
		spanSlice = append(spanSlice, inst)
	}
	return
}
