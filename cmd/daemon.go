package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	dv_cmd "github.com/named-data/ndnd/dv/cmd"
	dv_config "github.com/named-data/ndnd/dv/config"
	fw_cmd "github.com/named-data/ndnd/fw/cmd"
	fw_core "github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/std/utils"
	"github.com/named-data/ndnd/std/utils/toolutils"
	"github.com/spf13/cobra"
)

var cmdDaemon = &cobra.Command{
	Use:     "daemon CONFIG-FILE",
	Short:   "NDN Combined Daemon",
	Long:    "NDN Forwarder-Router combined daemon",
	Example: `  https://github.com/named-data/ndnd/blob/main/docs/daemon-example.md`,
	GroupID: "daemons",
	Version: utils.NDNdVersion,
	Args:    cobra.ExactArgs(1),
	Run:     daemon,
}

// daemon runs the combined forwarder-router daemon.
func daemon(_ *cobra.Command, args []string) {
	config := struct {
		Fw *fw_core.Config   `json:"fw"`
		Dv *dv_config.Config `json:"dv"`
	}{
		Fw: fw_core.DefaultConfig(),
		Dv: dv_config.DefaultConfig(),
	}
	toolutils.ReadYaml(&config, args[0])
	config.Fw.Core.BaseDir = filepath.Dir(args[0])
	if config.Fw.Fw.RouterName == "" && config.Dv != nil && config.Dv.Router != "" {
		config.Fw.Fw.RouterName = config.Dv.Router
	}

	// validate unix socket is enabled
	if !config.Fw.Faces.Unix.Enabled {
		panic("Unix socket must be enabled for the combined daemon")
	}

	// point dv to the correct socket
	sock := config.Fw.Faces.Unix.SocketPath
	if runtime.GOOS != "windows" { // wrong slashes
		sock = config.Fw.ResolveRelPath(sock)
	}
	os.Setenv("NDN_CLIENT_TRANSPORT", fmt.Sprintf("unix://%s", sock))

	// setup signals
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)

	// yanfd does not block on start
	yanfd := fw_cmd.NewYaNFD(config.Fw)
	yanfd.Start()

	// Give time for YanFD to start
	time.Sleep(1 * time.Second)

	// dve blocks on start, so run it in a goroutine
	dve, err := dv_cmd.NewDvExecutor(config.Dv)
	if err != nil {
		panic(err)
	}

	go func() {
		dve.Start()
		sigchan <- syscall.SIGTERM
	}()

	// wait for signal
	<-sigchan
	dve.Stop()
	<-sigchan
	yanfd.Stop()
}
