package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"

	gen "github.com/qabalwrap/qabalwrap-1/gen/qbw1diagrpcgen"
)

type commandRunner interface {
	// Name return command name.
	Name() string

	// SetFlags init given flag set.
	SetFlags(flagSet *flag.FlagSet)

	// CheckFlags will be invoke after flagSet.Parse() called.
	// Return non-nil error if any unexpect flag values is given.
	CheckFlags() (err error)

	// Run perform command operation.
	Run(ctx context.Context, client gen.Qabalwrap1DiagnosisGRPCClient) (err error)
}

type commandInstance struct {
	cmdRunner commandRunner
	flagSet   *flag.FlagSet
}

// ErrRequireConfigurationFile indicates configuration file is missing.
var ErrRequireConfigurationFile = errors.New("configuration file is required")

// ErrRequireValidSubCommand indicate valid sub-command is not given.
var ErrRequireValidSubCommand = errors.New("need valid sub-command")

// ErrRequireTargetDiagnosisServerAddress indicate diagnosis service address is not given.
var ErrRequireTargetDiagnosisServerAddress = errors.New("require target diagnosis server address")

func parseCommandParam(cmdRunners ...commandRunner) (diagnosisServerAddr string, chosenRunner commandRunner, err error) {
	cmdInstMap := make(map[string]*commandInstance)
	availableCommands := make([]string, 0, len(cmdRunners))
	for _, cmdR := range cmdRunners {
		cmdName := cmdR.Name()
		flagSet := flag.NewFlagSet(cmdName, flag.ExitOnError)
		flagSet.StringVar(&diagnosisServerAddr, "host", "", "service address of diagnosis socket")
		cmdR.SetFlags(flagSet)
		cmdInstMap[cmdName] = &commandInstance{
			cmdRunner: cmdR,
			flagSet:   flagSet,
		}
		availableCommands = append(availableCommands, cmdName)
	}
	if len(os.Args) < 2 {
		err = ErrRequireValidSubCommand
		return
	}
	chosenCmd := os.Args[1]
	cmdInst := cmdInstMap[chosenCmd]
	if cmdInst == nil {
		log.Printf("WARN: available commands: %v", availableCommands)
		err = ErrRequireValidSubCommand
		return
	}
	cmdInst.flagSet.Parse(os.Args[2:])
	if diagnosisServerAddr == "" {
		err = ErrRequireTargetDiagnosisServerAddress
		return
	}
	if err = cmdInst.cmdRunner.CheckFlags(); nil != err {
		return
	}
	chosenRunner = cmdInst.cmdRunner
	return
}
