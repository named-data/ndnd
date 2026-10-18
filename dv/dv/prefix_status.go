package dv

import (
	"slices"
	"strings"

	"github.com/named-data/ndnd/dv/table"
	"github.com/named-data/ndnd/dv/tlv"
)

func makePrefixStateStatus(entries []table.PrefixSnapshotEntry) *tlv.PrefixStateStatus {
	slices.SortFunc(entries, func(a, b table.PrefixSnapshotEntry) int {
		if order := strings.Compare(a.Name.TlvStr(), b.Name.TlvStr()); order != 0 {
			return order
		}
		return strings.Compare(a.Router.TlvStr(), b.Router.TlvStr())
	})

	status := &tlv.PrefixStateStatus{
		Version: tlv.PrefixStateStatusVersion,
		Entries: make([]*tlv.PrefixStateStatusEntry, 0, len(entries)),
	}
	for _, entry := range entries {
		nextHops := slices.Clone(entry.NextHops)
		slices.SortFunc(nextHops, func(a, b table.PrefixNextHop) int {
			if a.Face < b.Face {
				return -1
			}
			if a.Face > b.Face {
				return 1
			}
			if a.Cost < b.Cost {
				return -1
			}
			if a.Cost > b.Cost {
				return 1
			}
			return 0
		})

		statusEntry := &tlv.PrefixStateStatusEntry{
			Name:           entry.Name,
			Router:         entry.Router,
			Multicast:      entry.Multicast,
			ValidityPeriod: entry.ValidityPeriod,
			NextHops:       make([]*tlv.PrefixStateNextHop, 0, len(nextHops)),
		}
		for _, nextHop := range nextHops {
			statusEntry.NextHops = append(statusEntry.NextHops, &tlv.PrefixStateNextHop{
				Face: nextHop.Face,
				Cost: nextHop.Cost,
			})
		}
		status.Entries = append(status.Entries, statusEntry)
	}
	return status
}
