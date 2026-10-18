package dvc

import (
	"fmt"
	"os"
	"time"

	spec_dv "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
	"github.com/spf13/cobra"
)

// (AI GENERATED DESCRIPTION): Builds and returns the Cobra command set for querying router status, creating a new active neighbor link, and destroying an existing neighbor link.
func Cmds() []*cobra.Command {
	t := Tool{}

	return []*cobra.Command{{
		Use:   "status",
		Short: "Print general status of the router",
		Args:  cobra.NoArgs,
		Run:   t.RunDvStatus,
	}, {
		Use:   "prefix-announce [params]",
		Short: "Announce a prefix in the DV prefix state (non-expiring by default)",
		Args:  cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			t.ExecPrefixCmd(cmd, "announce", args, []string{})
		},
	}, {
		Use:   "prefix-withdraw [params]",
		Short: "Withdraw a prefix from the DV prefix state",
		Args:  cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			t.ExecPrefixCmd(cmd, "withdraw", args, []string{})
		},
	}, {
		Use:   "prefix-list",
		Short: "List prefix state entries",
		Args:  cobra.NoArgs,
		Run:   t.RunDVPrefixList,
	}, {
		Use:   "link-create NEIGHBOR-URI",
		Short: "Create a new active neighbor link",
		Args:  cobra.ExactArgs(1),
		Run:   t.RunDvLinkCreate,
	}, {
		Use:   "link-destroy NEIGHBOR-URI",
		Short: "Destroy an active neighbor link",
		Args:  cobra.ExactArgs(1),
		Run:   t.RunDvLinkDestroy,
	}}
}

type Tool struct {
	engine ndn.Engine
}

func (t *Tool) RunDVPrefixList(_ *cobra.Command, _ []string) {
	t.Start()
	defer t.Stop()

	name := enc.Name{
		enc.LOCALHOST,
		enc.NewGenericComponent("dv"),
		enc.NewGenericComponent("prefix"),
		enc.NewGenericComponent("list"),
	}
	cfg := &ndn.InterestConfig{
		MustBeFresh: true,
		Lifetime:    optional.Some(time.Second),
		Nonce:       utils.ConvertNonce(t.engine.Timer().Nonce()),
	}
	interest, err := t.engine.Spec().MakeInterest(name, cfg, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create prefix-list Interest: %+v\n", err)
		os.Exit(1)
		return
	}

	responses := make(chan ndn.ExpressCallbackArgs, 1)
	if err := t.engine.Express(interest, func(args ndn.ExpressCallbackArgs) { responses <- args }); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to express prefix-list Interest: %+v\n", err)
		os.Exit(1)
		return
	}
	response := <-responses
	if response.Result != ndn.InterestResultData {
		fmt.Fprintf(os.Stderr, "prefix-list Interest failed: %s\n", response.Result)
		os.Exit(1)
		return
	}

	status, err := spec_dv.ParsePrefixStateStatus(enc.NewWireView(response.Data.Content()), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse prefix-list dataset: %+v\n", err)
		os.Exit(1)
		return
	}
	if status.Version != spec_dv.PrefixStateStatusVersion {
		fmt.Fprintf(os.Stderr, "Unsupported prefix-list dataset version: %d\n", status.Version)
		os.Exit(1)
		return
	}

	fmt.Printf("Prefix state (version %d):\n", status.Version)
	if len(status.Entries) == 0 {
		fmt.Println("  (empty)")
		return
	}
	for _, entry := range status.Entries {
		fmt.Printf("  prefix=%s router=%s multicast=%t", entry.Name, entry.Router, entry.Multicast)
		if validity := entry.ValidityPeriod; validity != nil {
			fmt.Printf(" validity={not-before=%q not-after=%q}", validity.NotBefore, validity.NotAfter)
		}
		fmt.Print(" nexthops={")
		for i, nextHop := range entry.NextHops {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("face=%d(cost=%d)", nextHop.Face, nextHop.Cost)
		}
		fmt.Println("}")
	}
}

// (AI GENERATED DESCRIPTION): Initializes the Tool’s engine with a default face and starts it, terminating the program if the engine fails to start.
func (t *Tool) Start() {
	t.engine = engine.NewBasicEngine(engine.NewDefaultFace())

	err := t.engine.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start engine: %+v\n", err)
		os.Exit(1)
		return
	}
}

// (AI GENERATED DESCRIPTION): Stops the Tool’s engine, terminating its operation.
func (t *Tool) Stop() {
	t.engine.Stop()
}
