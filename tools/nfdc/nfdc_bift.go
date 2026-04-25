package nfdc

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/named-data/ndnd/fw/bier"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/spf13/cobra"
)

// BiftCmds returns the BIFT-related CLI commands.
func (t *Tool) BiftCmds() []*cobra.Command {
	cmd := func(verb string, defaults []string) func(*cobra.Command, []string) {
		return func(c *cobra.Command, args []string) {
			t.ExecCmd(c, "bift", verb, args, defaults)
		}
	}

	return []*cobra.Command{{
		Use:   "bift-list",
		Short: "Print BIFT entries",
		Args:  cobra.NoArgs,
		Run:   t.ExecBiftList,
	}, {
		Use:   "bift-register [params]",
		Short: "Register a router BFR-ID",
		Args:  cobra.ArbitraryArgs,
		Run: cmd("register", []string{
			"index=0",
		}),
	}, {
		Use:   "bift-rebuild",
		Short: "Rebuild BIFT from FIB/PET",
		Args:  cobra.NoArgs,
		Run:   cmd("rebuild", []string{}),
	}}
}

// ExecBiftList retrieves the BIFT status dataset, parses it, and prints BIFT entries.
func (t *Tool) ExecBiftList(_ *cobra.Command, _ []string) {
	t.Start()
	defer t.Stop()

	suffix := enc.Name{
		enc.NewGenericComponent("bift"),
		enc.NewGenericComponent("list"),
	}

	data, err := t.fetchStatusDataset(suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching status dataset: %+v\n", err)
		os.Exit(1)
		return
	}

	var status bier.BiftStatus
	if err := json.Unmarshal(data.Join(), &status); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing BIFT status: %+v\n", err)
		os.Exit(1)
		return
	}

	fmt.Printf("BIFT: bier-index=%d\n", status.BierIndex)
	for _, entry := range status.Entries {
		fmt.Printf("  index=%d router=%s nexthops={%s} fbm={%s}\n",
			entry.BfrId, entry.RouterName, formatBiftNextHops(entry.NextHops), formatBitList(entry.FbmBits))
	}

	if len(status.Neighbors) == 0 {
		return
	}

	fmt.Println("BIFT neighbors:")
	for _, neighbor := range status.Neighbors {
		fmt.Printf("  faceid=%d fbm={%s}\n", neighbor.FaceID, formatBitList(neighbor.FbmBits))
	}
}

func formatBitList(bits []int) string {
	if len(bits) == 0 {
		return ""
	}

	parts := make([]string, 0, len(bits))
	for _, bit := range bits {
		parts = append(parts, strconv.Itoa(bit))
	}
	return strings.Join(parts, ", ")
}

func formatBiftNextHops(nextHops []uint64) string {
	parts := make([]string, 0, len(nextHops))
	for _, faceID := range nextHops {
		parts = append(parts, fmt.Sprintf("faceid=%d", faceID))
	}
	return strings.Join(parts, ", ")
}
