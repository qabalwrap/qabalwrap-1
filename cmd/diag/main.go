package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"

	runner_exporttrace "github.com/qabalwrap/qabalwrap-1/cmd/diag/internal/exporttrace"
	runner_ping "github.com/qabalwrap/qabalwrap-1/cmd/diag/internal/ping"
	runner_readtrace "github.com/qabalwrap/qabalwrap-1/cmd/diag/internal/readtrace"
)

func main() {
	diagnosisServerAddr, chosenRunner, err := parseCommandParam(
		&runner_readtrace.Runner{},
		&runner_exporttrace.Runner{},
		&runner_ping.Runner{})
	if nil != err {
		log.Fatalf("ERROR: parse command option failed: %v", err)
	}
	if diagnosisServerAddr[0] == '/' {
		diagnosisServerAddr = "unix://" + diagnosisServerAddr
	} else {
		diagnosisServerAddr = "dns:///" + diagnosisServerAddr
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(diagnosisServerAddr, opts...)
	if err != nil {
		log.Fatalf("ERROR: fail to dial: %v", err)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := gen.NewQabalwrap1DiagnosisGRPCClient(conn)
	if err = chosenRunner.Run(ctx, client); nil != err {
		log.Fatalf("ERROR: run command [%s] failed: %v", chosenRunner.Name(), err)
	} else {
		log.Printf("INFO: command [%s] completed.", chosenRunner.Name())
	}
}
