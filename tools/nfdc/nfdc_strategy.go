package nfdc

import (
	"fmt"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

func (n *Nfdc) ExecStrategyList(args []string) {
	suffix := enc.Name{
		enc.NewStringComponent(enc.TypeGenericNameComponent, "strategy-choice"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "list"),
	}

	data, err := n.fetchStatusDataset(suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching status dataset: %+v\n", err)
		return
	}

	status, err := mgmt.ParseStrategyChoiceMsg(enc.NewBufferReader(data), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing strategy list: %+v\n", err)
		return
	}

	for _, entry := range status.StrategyChoices {
		if entry.Strategy != nil {
			fmt.Printf("prefix=%s strategy=%s\n", entry.Name, entry.Strategy.Name)
		}
	}
}
