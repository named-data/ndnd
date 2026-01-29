package nfdc

import (
	"fmt"
	"os"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/utils/toolutils"
	"github.com/spf13/cobra"
)

// (AI GENERATED DESCRIPTION): Retrieves the NFD general status dataset, parses the returned data, and prints a formatted summary of the node’s runtime statistics to standard output.
func (t *Tool) ExecStatusGeneral(_ *cobra.Command, args []string) {
	t.Start()
	defer t.Stop()

	suffix := enc.Name{
		enc.NewGenericComponent("status"),
		enc.NewGenericComponent("general"),
	}

	data, err := t.fetchStatusDataset(suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching status dataset: %+v\n", err)
		os.Exit(1)
		return
	}

	status, err := mgmt.ParseGeneralStatus(enc.NewWireView(data), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing general status: %+v\n", err)
		os.Exit(1)
		return
	}

	p := toolutils.StatusPrinter{File: os.Stdout, Padding: 24}
	fmt.Println("General NFD status:")
	p.Print("version", status.NfdVersion)
	p.Print("startTime", time.Unix(0, int64(status.StartTimestamp)))
	p.Print("currentTime", time.Unix(0, int64(status.CurrentTimestamp)))
	p.Print("uptime", (status.CurrentTimestamp - status.StartTimestamp))
	p.Print("nNameTreeEntries", status.NNameTreeEntries)
	p.Print("nFibEntries", status.NFibEntries)
	p.Print("nPitEntries", status.NPitEntries)
	p.Print("nMeasurementsEntries", status.NMeasurementsEntries)
	p.Print("nCsEntries", status.NCsEntries)
	p.Print("nInInterests", status.NInInterests)
	p.Print("nOutInterests", status.NOutInterests)
	p.Print("nInData", status.NInData)
	p.Print("nOutData", status.NOutData)
	p.Print("nInNacks", status.NInNacks)
	p.Print("nOutNacks", status.NOutNacks)
	p.Print("nSatisfiedInterests", status.NSatisfiedInterests)
	p.Print("nUnsatisfiedInterests", status.NUnsatisfiedInterests)
}
