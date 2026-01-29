package repo

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/utils"
	"github.com/named-data/ndnd/std/utils/toolutils"
	"github.com/spf13/cobra"
)

var CmdRepo = &cobra.Command{
	Use:     "repo CONFIG-FILE",
	Short:   "Named Data Networking Data Repository",
	GroupID: "run",
	Version: utils.NDNdVersion,
	Args:    cobra.ExactArgs(1),
	Run:     run,
}

// (AI GENERATED DESCRIPTION): Initializes the repository using a YAML configuration, starts it, and blocks until an interrupt or SIGTERM signal is received to gracefully stop the repository.
func run(cmd *cobra.Command, args []string) {
	config := struct {
		Repo *Config `json:"repo"`
	}{
		Repo: DefaultConfig(),
	}
	toolutils.ReadYaml(&config, args[0])

	if err := config.Repo.Parse(); err != nil {
		log.Fatal(nil, "Configuration error", "err", err)
	}

	repo := NewRepo(config.Repo)
	err := repo.Start()
	if err != nil {
		log.Fatal(nil, "Failed to start repo", "err", err)
	}
	defer repo.Stop()

	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	<-sigChannel
}
