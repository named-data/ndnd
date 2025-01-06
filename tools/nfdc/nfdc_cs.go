package nfdc

import (
	"fmt"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

func (n *Nfdc) ExecCsInfo(args []string) {
	suffix := enc.Name{
		enc.NewStringComponent(enc.TypeGenericNameComponent, "cs"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "info"),
	}

	data, err := n.fetchStatusDataset(suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching status dataset: %+v\n", err)
		return
	}

	status, err := mgmt.ParseCsInfoMsg(enc.NewBufferReader(data), true)
	if err != nil || status.CsInfo == nil {
		fmt.Fprintf(os.Stderr, "Error parsing CS info: %+v\n", err)
		return
	}

	info := status.CsInfo

	fmt.Println("CS information:")
	n.statusPadding = 10
	n.printStatusLine("capacity", info.Capacity)
	n.printStatusLine("admit", info.Flags&mgmt.CsEnableAdmit != 0)
	n.printStatusLine("serve", info.Flags&mgmt.CsEnableServe != 0)
	n.printStatusLine("nEntries", info.NCsEntries)
	n.printStatusLine("nHits", info.NHits)
	n.printStatusLine("nMisses", info.NMisses)
}
