package nfdc

import (
	"fmt"
	"os"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/spf13/cobra"
)

// (AI GENERATED DESCRIPTION): ExecPibList retrieves the PIB status dataset, parses it, and prints each PIB entry with its egress routers and nexthops.
func (t *Tool) ExecPibList(_ *cobra.Command, _ []string) {
	t.Start()
	defer t.Stop()

	suffix := enc.Name{
		enc.NewGenericComponent("pib"),
		enc.NewGenericComponent("list"),
	}

	data, err := t.fetchStatusDataset(suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching status dataset: %+v\n", err)
		os.Exit(1)
		return
	}

	status, err := mgmt.ParsePibStatus(enc.NewWireView(data), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing PIB status: %+v\n", err)
		os.Exit(1)
		return
	}

	fmt.Println("PIB:")
	for _, entry := range status.Entries {
		egressList := make([]string, 0, len(entry.EgressRecords))
		for _, egress := range entry.EgressRecords {
			egressList = append(egressList, egress.Name.String())
		}

		nexthops := make([]string, 0, len(entry.NextHopRecords))
		for _, record := range entry.NextHopRecords {
			nexthops = append(nexthops, fmt.Sprintf("faceid=%d (cost=%d)", record.FaceId, record.Cost))
		}

		fmt.Printf("  %s egress={%s} nexthops={%s}\n",
			entry.Name, strings.Join(egressList, ", "), strings.Join(nexthops, ", "))
	}
}
