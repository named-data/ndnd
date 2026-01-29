package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/std/utils"
	"github.com/named-data/ndnd/std/utils/toolutils"
	"github.com/spf13/cobra"
)

var CmdDv = &cobra.Command{
	Use:     "ndn-dv CONFIG-FILE",
	Short:   "NDN Distance Vector Routing Daemon",
	GroupID: "run",
	Version: utils.NDNdVersion,
	Args:    cobra.ExactArgs(1),
	Run:     run,
}

// (AI GENERATED DESCRIPTION): Initializes a DvExecutor from a YAML configuration file and runs it until an interrupt (Ctrl‑C or SIGTERM) is received, at which point it stops the executor and exits.
func run(cmd *cobra.Command, args []string) {
	configfile := args[0]

	config := struct {
		Config *config.Config `json:"dv"`
	}{
		Config: config.DefaultConfig(),
	}
	toolutils.ReadYaml(&config, configfile)

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)

	dve, err := NewDvExecutor(config.Config)
	if err != nil {
		panic(err)
	}

	go func() {
		dve.Start()
		sigchan <- syscall.SIGTERM
	}()

	// wait for interrupt
	<-sigchan
	dve.Stop()
	<-sigchan
}
