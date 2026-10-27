package nfdc

import (
	"fmt"
	"os"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/spf13/cobra"
)

// ExecPetList retrieves PET status dataset, parses it, and prints PET entries.
func (t *Tool) ExecPetList(_ *cobra.Command, _ []string) {
	t.Start()
	defer t.Stop()

	status, err := t.fetchPetStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching PET status: %+v\n", err)
		os.Exit(1)
		return
	}

	fmt.Println("PET:")
	for _, entry := range status.Entries {
		egressList := make([]string, 0, len(entry.EgressRecords))
		for _, egress := range entry.EgressRecords {
			egressList = append(egressList, egress.Name.String())
		}

		nexthops := make([]string, 0, len(entry.NextHopRecords))
		for _, record := range entry.NextHopRecords {
			nexthops = append(nexthops, fmt.Sprintf("faceid=%d (cost=%d)", record.FaceId, record.Cost))
		}

		multicastStr := ""
		if entry.Multicast {
			multicastStr = " [multicast]"
		}

		fmt.Printf("  %s egress={%s} nexthops={%s}%s\n",
			entry.Name, strings.Join(egressList, ", "), strings.Join(nexthops, ", "), multicastStr)
	}
}

func (t *Tool) fetchPetStatus() (*mgmt.PetStatus, error) {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("pet"), enc.NewGenericComponent("list")})
	if err != nil {
		return nil, fmt.Errorf("fetch PET: %w", err)
	}
	status, err := mgmt.ParsePetStatus(enc.NewWireView(data), true)
	if err != nil {
		return nil, fmt.Errorf("parse PET: %w", err)
	}
	return status, nil
}
