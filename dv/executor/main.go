package executor

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/goccy/go-yaml"
)

func Main(args []string) {
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config-file>\n", args[0])
		os.Exit(2)
	}

	cfgBytes, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read configuration file: %s\n", err)
		os.Exit(3)
	}

	dc := DefaultConfig()
	if err = yaml.Unmarshal(cfgBytes, &dc); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse configuration file: %s\n", err)
		os.Exit(3)
	}

	dve, err := NewDvExecutor(dc)
	if err != nil {
		panic(err)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)

	quitchan := make(chan bool, 1)
	go func() {
		if err = dve.Start(); err != nil {
			panic(err)
		}
		quitchan <- true
	}()

	for {
		select {
		case <-sigchan:
			dve.Stop()
		case <-quitchan:
			return
		}
	}
}
