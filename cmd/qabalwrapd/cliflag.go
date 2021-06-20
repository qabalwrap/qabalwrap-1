package main

import (
	"context"
	"errors"
	"flag"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
)

// ErrRequireConfigurationFile indicates configuration file is missing.
var ErrRequireConfigurationFile = errors.New("configuration file is required")

func parseCommandParam() (ctx context.Context, cancel context.CancelFunc, msgSwitch *qabalwrap.MessageSwitch, err error) {
	var configFilePath string
	flag.StringVar(&configFilePath, "conf", "", "path to configuration")
	flag.Parse()
	if "" == configFilePath {
		err = ErrRequireConfigurationFile
		return
	}
	cfg, err := loadConfiguration(configFilePath)
	if nil != err {
		return
	}
	return cfg.makeInstance()
}
