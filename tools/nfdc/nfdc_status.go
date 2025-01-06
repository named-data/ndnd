package nfdc

import (
	"fmt"
	"os"
	"strings"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

func (n *Nfdc) ExecStatusGeneral(args []string) {
	suffix := enc.Name{
		enc.NewStringComponent(enc.TypeGenericNameComponent, "status"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "general"),
	}

	data, err := n.fetchStatusDataset(suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching status dataset: %+v\n", err)
		return
	}

	status, err := mgmt.ParseGeneralStatus(enc.NewBufferReader(data), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing general status: %+v\n", err)
		return
	}

	fmt.Println("General NFD status:")
	n.statusPadding = 24
	n.printStatusLine("version", status.NfdVersion)
	n.printStatusLine("startTime", time.Unix(0, int64(status.StartTimestamp)))
	n.printStatusLine("currentTime", time.Unix(0, int64(status.CurrentTimestamp)))
	n.printStatusLine("uptime", (status.CurrentTimestamp - status.StartTimestamp))
	n.printStatusLine("nNameTreeEntries", status.NNameTreeEntries)
	n.printStatusLine("nFibEntries", status.NFibEntries)
	n.printStatusLine("nPitEntries", status.NCsEntries)
	n.printStatusLine("nMeasurementsEntries", status.NMeasurementsEntries)
	n.printStatusLine("nCsEntries", status.NCsEntries)
	n.printStatusLine("nInInterests", status.NInInterests)
	n.printStatusLine("nOutInterests", status.NOutInterests)
	n.printStatusLine("nInData", status.NInData)
	n.printStatusLine("nOutData", status.NOutData)
	n.printStatusLine("nInNacks", status.NInNacks)
	n.printStatusLine("nOutNacks", status.NOutNacks)
	n.printStatusLine("nSatisfiedInterests", status.NSatisfiedInterests)
	n.printStatusLine("nUnsatisfiedInterests", status.NUnsatisfiedInterests)
}

func (n *Nfdc) printStatusLine(key string, value any) {
	padding := n.statusPadding - len(key)
	fmt.Printf("%s%s=%v\n", strings.Repeat(" ", padding), key, value)
}
