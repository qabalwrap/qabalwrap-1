package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"
)

func main() {
	diagnosisServerAddr, chosenRunner, err := parseCommandParam(
		&readTraceRunner{},
		&pingRunner{})
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
