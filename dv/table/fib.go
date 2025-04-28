package table

import (
	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

type FibEntry struct {
	// next hop face Id
	FaceId uint64
	// cost in this entry
	Cost uint64
	// previous cost
	prevCost uint64
}

// Get the FIB entry for a name prefix.
// router should be hash of the router name.
func (rib *Rib) GetFibEntries(nt *NeighborTable, router uint64) (entries []FibEntry) {
	ribEntry := rib.entries[router]
	entries = make([]FibEntry, 0, 2)

	if ns := nt.GetH(ribEntry.nextHop1); ns != nil && ribEntry.lowest1 < config.CostInfinity {
		entries = append(entries, FibEntry{
			FaceId: ns.faceId,
			Cost:   ribEntry.lowest1,
		})
	}
	if ns := nt.GetH(ribEntry.nextHop2); ns != nil && ribEntry.lowest2 < config.CostInfinity {
		entries = append(entries, FibEntry{
			FaceId: ns.faceId,
			Cost:   ribEntry.lowest2,
		})
	}

	return entries
}

type Fib struct {
	config   *config.Config
	nfdc     *nfdc.NfdMgmtThread
	names    map[uint64]enc.Name
	prefixes map[uint64][]FibEntry
	mark     map[uint64]bool
}

func NewFib(config *config.Config, nfdc *nfdc.NfdMgmtThread) *Fib {
	return &Fib{
		config:   config,
		nfdc:     nfdc,
		names:    make(map[uint64]enc.Name),
		prefixes: make(map[uint64][]FibEntry),
		mark:     make(map[uint64]bool),
	}
}

func (fib *Fib) Size() int {
	return len(fib.prefixes)
}

func (fib *Fib) Update(name enc.Name, newEntries []FibEntry) bool {
	return fib.UpdateH(name.Hash(), name, newEntries)
}

func (fib *Fib) UpdateH(nameH uint64, name enc.Name, newEntries []FibEntry) bool {
	if _, ok := fib.names[nameH]; !ok {
		fib.names[nameH] = name
	}

	// Set cost of all current entries to infinite and store existing params
	oldEntries := fib.prefixes[nameH]
	for oi := range oldEntries {
		oldEntries[oi].prevCost = oldEntries[oi].Cost
		oldEntries[oi].Cost = config.CostPfxInfinity
	}

	// Merge new entries into old entries
	for _, newEntry := range newEntries {
		// Likely from RIB computation
		if newEntry.Cost >= config.CostPfxInfinity {
			continue
		}

		// Check if same face already exists, in that case
		// just update the cost and other parameters
		found := false
		for oi := range oldEntries {
			if oldEntries[oi].FaceId == newEntry.FaceId {
				// Use the lowest cost known to us. This is needed since the
				// new entries may have some duplicates, e.g. multi-homed prefixes
				oldEntries[oi].Cost = min(newEntry.Cost, oldEntries[oi].Cost)

				// oldEntries is guaranteed to not have duplicates
				found = true
				break
			}
		}

		// If a matching face entry was not found, add the new one
		if !found {
			newEntry.prevCost = config.CostPfxInfinity
			oldEntries = append(oldEntries, newEntry)
		}
	}

	// Unregister entries that are not reachable
	finalEntries := make([]FibEntry, 0, len(oldEntries))
	for _, oldEntry := range oldEntries {
		if oldEntry.Cost >= config.CostPfxInfinity {
			fib.nfdc.Exec(nfdc.NfdMgmtCmd{
				Module: "rib",
				Cmd:    "unregister",
				Args: &mgmt.ControlArgs{
					Name:   name,
					FaceId: optional.Some(oldEntry.FaceId),
					Origin: optional.Some(config.NlsrOrigin),
				},
				Retries: 3,
			})
		} else {
			finalEntries = append(finalEntries, oldEntry)
		}
	}

	// Update all current entries
	for _, entry := range finalEntries {
		// If all params are the same, skip
		if entry.Cost == entry.prevCost {
			continue
		}

		fib.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "register",
			Args: &mgmt.ControlArgs{
				Name:   name,
				FaceId: optional.Some(entry.FaceId),
				Cost:   optional.Some(entry.Cost),
				Origin: optional.Some(config.NlsrOrigin),
			},
			Retries: 3,
		})
	}

	if len(finalEntries) > 0 {
		fib.prefixes[nameH] = finalEntries
		return true
	} else {
		delete(fib.prefixes, nameH)
		delete(fib.mark, nameH)
		delete(fib.names, nameH)
		return false
	}
}

func (fib *Fib) MarkH(name uint64) {
	fib.mark[name] = true
}

func (fib *Fib) UnmarkAll() {
	for hash := range fib.mark {
		delete(fib.mark, hash)
	}
}

func (fib *Fib) RemoveUnmarked() {
	for nh := range fib.prefixes {
		if !fib.mark[nh] {
			if name := fib.names[nh]; name != nil {
				fib.UpdateH(nh, name, nil)
			}
		}
	}
}
