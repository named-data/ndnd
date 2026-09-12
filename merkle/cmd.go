package merkle

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/utils"
	"github.com/named-data/ndnd/std/utils/toolutils"
	"github.com/spf13/cobra"
)

// CmdMerkle starts the Merkle history log daemon.
var CmdMerkle = &cobra.Command{
	Use:     "merkle CONFIG-FILE",
	Short:   "Merkle history log",
	GroupID: "run",
	Version: utils.NDNdVersion,
	Args:    cobra.ExactArgs(1),
	Run:     run,
}

func run(cmd *cobra.Command, args []string) {
	config := struct {
		Merkle *Config `json:"merkle"`
	}{
		Merkle: DefaultConfig(),
	}
	toolutils.ReadYaml(&config, args[0])
	if config.Merkle == nil {
		log.Fatal(nil, "Configuration error", "err", errors.New("merkle configuration is missing"))
	}

	service := NewLog(config.Merkle)
	if err := service.Start(); err != nil {
		log.Fatal(nil, "Failed to start Merkle history log", "err", err)
	}
	defer service.Stop()

	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChannel)
	<-sigChannel
}
