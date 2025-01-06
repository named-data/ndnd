package executor

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/goccy/go-yaml"
	"github.com/named-data/ndnd/fw/core"
)

var Version string

func Main(args []string) {
	config := &YaNFDConfig{}

	flagset := flag.NewFlagSet("yanfd", flag.ExitOnError)
	flagset.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <config-file>\n", args[0])
		flagset.PrintDefaults()
	}

	var printVersion bool
	flagset.BoolVar(&printVersion, "version", false, "Print version and exit")

	flagset.StringVar(&config.CpuProfile, "cpu-profile", "", "Enable CPU profiling (output to specified file)")
	flagset.StringVar(&config.MemProfile, "mem-profile", "", "Enable memory profiling (output to specified file)")
	flagset.StringVar(&config.BlockProfile, "block-profile", "", "Enable block profiling (output to specified file)")
	flagset.IntVar(&config.MemoryBallastSize, "memory-ballast", 0, "Enable memory ballast of specified size (in GB) to avoid frequent garbage collection")

	flagset.Parse(args[1:])

	if printVersion {
		fmt.Fprintln(os.Stderr, "YaNFD: Yet another NDN Forwarding Daemon")
		fmt.Fprintln(os.Stderr, "Version: ", Version)
		fmt.Fprintln(os.Stderr, "Copyright (C) 2020-2024 University of California")
		fmt.Fprintln(os.Stderr, "Released under the terms of the MIT License")
		return
	}

	configfile := flagset.Arg(0)
	if flagset.NArg() != 1 || configfile == "" {
		flagset.Usage()
		os.Exit(3)
	}
	config.BaseDir = filepath.Dir(configfile)

	f, err := os.Open(configfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to open configuration file: "+err.Error())
		os.Exit(3)
	}
	defer f.Close()

	config.Config = core.DefaultConfig()
	dec := yaml.NewDecoder(f, yaml.Strict())
	if err = dec.Decode(config.Config); err != nil {
		fmt.Fprintln(os.Stderr, "Unable to parse configuration file: "+err.Error())
		os.Exit(3)
	}

	// create YaNFD instance
	yanfd := NewYaNFD(config)
	yanfd.Start()

	// set up signal handler channel and wait for interrupt
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	core.LogInfo(yanfd, "Received signal ", receivedSig, " - exiting")

	yanfd.Stop()
}
