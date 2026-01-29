package cmd

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/std/utils"
	"github.com/named-data/ndnd/std/utils/toolutils"
	"github.com/spf13/cobra"
)

var config = core.DefaultConfig()

var CmdYaNFD = &cobra.Command{
	Use:     "yanfd CONFIG-FILE",
	Short:   "Yet another NDN Forwarding Daemon",
	GroupID: "run",
	Version: utils.NDNdVersion,
	Args:    cobra.ExactArgs(1),
	Run:     run,
}

// (AI GENERATED DESCRIPTION): Registers CPU, memory, and block profiling flags for the YaNFD command, storing the chosen output filenames in the corresponding fields of `config.Core`.
func init() {
	CmdYaNFD.Flags().StringVar(&config.Core.CpuProfile, "cpu-profile", "", "Write CPU profile to file")
	CmdYaNFD.Flags().StringVar(&config.Core.MemProfile, "mem-profile", "", "Write memory profile to file")
	CmdYaNFD.Flags().StringVar(&config.Core.BlockProfile, "block-profile", "", "Write block profile to file")
}

// (AI GENERATED DESCRIPTION): Starts a YaNFD instance with the supplied configuration file and runs it until an interrupt or SIGTERM is received, at which point it logs the signal and gracefully stops the daemon.
func run(cmd *cobra.Command, args []string) {
	configfile := args[0]
	config.Core.BaseDir = filepath.Dir(configfile)

	// read configuration file
	toolutils.ReadYaml(config, configfile)

	// create YaNFD instance
	yanfd := NewYaNFD(config)
	yanfd.Start()

	// set up signal handler channel and wait for interrupt
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	core.Log.Info(yanfd, "Received signal - exit", "signal", receivedSig)

	yanfd.Stop()
}
