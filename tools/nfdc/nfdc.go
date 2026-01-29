package nfdc

import (
	"fmt"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/spf13/cobra"
)

// (AI GENERATED DESCRIPTION): Creates and returns the Cobra command hierarchy for the NDN command‑line tool, wiring each subcommand (e.g., status, face‑create, route‑add) to the appropriate Tool execution methods.
func Cmds() []*cobra.Command {
	t := Tool{}
	cmd := func(mod string, cmd string, defaults []string) func(*cobra.Command, []string) {
		return func(c *cobra.Command, args []string) {
			t.ExecCmd(c, mod, cmd, args, defaults)
		}
	}

	return []*cobra.Command{{
		Use:   "status",
		Short: "Print general status",
		Args:  cobra.NoArgs,
		Run:   t.ExecStatusGeneral,
	}, {
		Use:   "face-list",
		Short: "Print face table",
		Args:  cobra.NoArgs,
		Run:   t.ExecFaceList,
	}, {
		Use:   "face-create [params]",
		Short: "Create a face",
		Args:  cobra.ArbitraryArgs,
		Run: cmd("faces", "create", []string{
			"persistency=persistent",
		}),
	}, {
		Use:   "face-destroy [params]",
		Short: "Destroy a face",
		Args:  cobra.ArbitraryArgs,
		Run:   cmd("faces", "destroy", []string{}),
	}, {
		Use:   "route-list",
		Short: "Print RIB routes",
		Args:  cobra.NoArgs,
		Run:   t.ExecRouteList,
	}, {
		Use:   "route-add [params]",
		Short: "Add a route to the RIB",
		Args:  cobra.ArbitraryArgs,
		Run: cmd("rib", "register", []string{
			"cost=0", "origin=255",
		}),
	}, {
		Use:   "route-remove [params]",
		Short: "Remove a route from the RIB",
		Args:  cobra.ArbitraryArgs,
		Run: cmd("rib", "unregister", []string{
			"origin=255",
		}),
	}, {
		Use:   "fib-list",
		Short: "Print FIB entries",
		Args:  cobra.NoArgs,
		Run:   t.ExecFibList,
	}, {
		Use:   "cs-info",
		Short: "Print content store info",
		Args:  cobra.NoArgs,
		Run:   t.ExecCsInfo,
	}, {
		Use:   "strategy-list",
		Short: "Print strategy choices",
		Args:  cobra.NoArgs,
		Run:   t.ExecStrategyList,
	}, {
		Use:   "strategy-set [params]",
		Short: "Set strategy choice",
		Args:  cobra.ArbitraryArgs,
		Run:   cmd("strategy-choice", "set", []string{}),
	}, {
		Use:   "strategy-unset [params]",
		Short: "Unset strategy choice",
		Args:  cobra.ArbitraryArgs,
		Run:   cmd("strategy-choice", "unset", []string{}),
	}}
}

type Tool struct {
	engine ndn.Engine
}

// (AI GENERATED DESCRIPTION): Initializes the tool's engine with a new BasicEngine using a default face if not already set, then starts the engine, exiting the program on startup failure.
func (t *Tool) Start() {
	if t.engine != nil {
		return
	}

	t.engine = engine.NewBasicEngine(engine.NewDefaultFace())
	err := t.engine.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start engine: %+v\n", err)
		os.Exit(1)
		return
	}
}

// (AI GENERATED DESCRIPTION): Stops the tool by invoking its underlying engine’s `Stop` method, terminating network activity.
func (t *Tool) Stop() {
	t.engine.Stop()
}

// (AI GENERATED DESCRIPTION): Returns the tool’s default name prefix, which is the NDN name “/localhost/nfd”.
func (t *Tool) Prefix() enc.Name {
	return enc.Name{
		enc.LOCALHOST,
		enc.NewGenericComponent("nfd"),
	}
}
