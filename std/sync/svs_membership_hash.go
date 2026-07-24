package sync

import (
	"crypto/sha256"
	"slices"

	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
)

// ComputeMembershipHash returns the membership hash over all (Name, BootstrapTime) pairs in state.
// Each tuple is encoded as a TLV structure (Tuple-T 0xcc with Name and BootstrapTime
// children) using the ndnd standard TLV codec.
func ComputeMembershipHash(state SvMap[uint64]) []byte {
	tuples := make([]*spec_svs.MembershipTuple, 0)
	for name, vals := range state.Iter() {
		for _, val := range vals {
			tuples = append(tuples, &spec_svs.MembershipTuple{
				Name:          name,
				BootstrapTime: val.Boot,
			})
		}
	}

	slices.SortFunc(tuples, func(a, b *spec_svs.MembershipTuple) int {
		if c := a.Name.Compare(b.Name); c != 0 {
			return c
		}
		if a.BootstrapTime < b.BootstrapTime {
			return -1
		}
		if a.BootstrapTime > b.BootstrapTime {
			return 1
		}
		return 0
	})

	h := sha256.New()
	for _, t := range tuples {
		h.Write(t.Encode().Join())
	}
	return h.Sum(nil)
}
