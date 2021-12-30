package diagnosissocket

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

type DiagnosisSocketServer struct {
	gen.UnimplementedQabalwrap1DiagnosisGRPCServer
	qabalwrap.ServiceBase

	diagnosisEmitter *qabalwrap.DiagnosisEmitter

	traceAccessControlLck sync.Mutex
	connectedTraceReader  map[string]int64

	listenAddr string
	grpcServer *grpc.Server

	messageSender qabalwrap.MessageSender
}

func NewDiagnosisSocketServer(listenAddr string) (diagServer *DiagnosisSocketServer) {
	return &DiagnosisSocketServer{
		connectedTraceReader: make(map[string]int64),
		listenAddr:           listenAddr,
	}
}

func (d *DiagnosisSocketServer) registConnectedTraceReader(readerInstIdent string) (registerTimestamp int64) {
	d.traceAccessControlLck.Lock()
	defer d.traceAccessControlLck.Unlock()
	registerTimestamp = time.Now().Unix()
	d.connectedTraceReader[readerInstIdent] = registerTimestamp
	return
}

func (d *DiagnosisSocketServer) verifyConnectedTraceReader(readerInstIdent string, registerTimestamp int64) (ok bool) {
	d.traceAccessControlLck.Lock()
	defer d.traceAccessControlLck.Unlock()
	v := d.connectedTraceReader[readerInstIdent]
	return (v == registerTimestamp)
}

func (d *DiagnosisSocketServer) unregistConnectedTraceReader(readerInstIdent string) {
	d.traceAccessControlLck.Lock()
	defer d.traceAccessControlLck.Unlock()
	delete(d.connectedTraceReader, readerInstIdent)
}

// Setup prepare provider for operation.
// Should only invoke at maintenance thread in setup stage.
func (d *DiagnosisSocketServer) Setup(
	diagnosisEmitter *qabalwrap.DiagnosisEmitter,
	certProvider qabalwrap.CertificateProvider) (err error) {
	d.diagnosisEmitter = diagnosisEmitter
	return
}

func (d *DiagnosisSocketServer) serveImpl(listener net.Listener, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	d.grpcServer.Serve(listener)
	log.Print("INFO: stopped DiagnosisSocket RPC listener")
}

// Start service instance for operation.
// Should only invoke at maintenance thread in setup stage.
func (d *DiagnosisSocketServer) Start(ctx context.Context, waitGroup *sync.WaitGroup) (err error) {
	grpcServer := grpc.NewServer()
	gen.RegisterQabalwrap1DiagnosisGRPCServer(grpcServer, d)
	var listener net.Listener
	if d.listenAddr[0] == '/' {
		listener, err = net.Listen("unix", d.listenAddr)
	} else {
		listener, err = net.Listen("tcp", d.listenAddr)
	}
	if nil != err {
		log.Printf("ERROR: (DiagnosisSocketServer.Start) failed to listen (%v): %v", d.listenAddr, err)
		grpcServer.Stop()
		return
	}
	d.grpcServer = grpcServer
	waitGroup.Add(1)
	go d.serveImpl(listener, waitGroup)
	return
}

// Stop service instance,
func (d *DiagnosisSocketServer) Stop() {
	if d.grpcServer != nil {
		d.grpcServer.Stop()
	}
}

// ReceiveMessage deliver message into this instance of service provider.
// The message should decypted before pass into this method.
func (d *DiagnosisSocketServer) ReceiveMessage(rawMessage *qabalwrap.EnvelopedMessage) (err error) {
	// TODO: impl
	return
}

// SetMessageSender bind given sender with this instance of service provider.
func (d *DiagnosisSocketServer) SetMessageSender(messageSender qabalwrap.MessageSender) {
	d.messageSender = messageSender
}
