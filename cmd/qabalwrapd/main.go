package main

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"golang.org/x/sys/unix"
)

func main() {
	ctx, cancel, msgSwitch, err := parseCommandParam()
	if nil != err {
		log.Fatalf("ERROR: cannot setup operation plane: %v", err)
		return
	}
	defer cancel()
	stopChannel := make(chan os.Signal, 1)
	signal.Notify(stopChannel, os.Interrupt, unix.SIGTERM)
	var waitGroup sync.WaitGroup
	log.Print("INFO: activating qabalwarp-1 service.")
	if err = msgSwitch.Start(ctx, &waitGroup, nil); nil != err {
		cancel()
		msgSwitch.Stop()
		log.Fatalf("ERROR: cannot start message switch: %v", err)
		return
	}
	log.Print("INFO: started qabalwarp-1 service.")
	select {
	case <-stopChannel:
		log.Print("INFO: having stop signal.")
		cancel()
	case <-ctx.Done():
		log.Print("INFO: having stopped context.")
	}
	log.Print("INFO: stopping qabalwarp-1 service.")
	msgSwitch.Stop()
	waitGroup.Wait()
	log.Print("INFO: stopped qabalwarp-1 service.")
}
