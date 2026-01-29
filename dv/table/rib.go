package table

import (
	"fmt"
	"iter"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
)

// Routing Information Base (RIB)
type Rib struct {
	// main router configuration
	config *config.Config
	// destination hash -> entry
	entries map[uint64]*RibEntry
	// neighbor hash -> neighbor name
	neighbors map[uint64]enc.Name
}

type RibEntry struct {
	// pointer to parent table
	rib *Rib
	// full name of destination router
	name enc.Name
	// neighbor hash -> cost
	costs map[uint64]uint64
	// next hop for lowest cost (name hash)
	nextHop1 uint64
	// second next hop for lowest cost (name hash)
	nextHop2 uint64
	// lowest cost in this entry
	lowest1 uint64
	// second lowest cost in this entry
	lowest2 uint64
	// needs refresh
	dirty bool
}

// (AI GENERATED DESCRIPTION): Creates a new Rib instance initialized with the supplied configuration and empty entry and neighbor maps.
func NewRib(config *config.Config) *Rib {
	return &Rib{
		config:    config,
		entries:   make(map[uint64]*RibEntry),
		neighbors: make(map[uint64]enc.Name),
	}
}

// Log identifier for the RIB.
func (r *Rib) String() string {
	return "dv-rib"
}

// Print the RIB to the console (for debugging).
func (r *Rib) Print() {
	for _, entry := range r.entries {
		fmt.Printf("=> Destination: %s\n", entry.name.String())
		for hop, cost := range entry.costs {
			if cost < config.CostInfinity {
				fmt.Printf("===> NextHop: %s, Cost: %d\n", r.neighbors[hop].String(), cost)
			}
		}
	}
}

// Size gets the number of entries in the RIB.
func (r *Rib) Size() int {
	return len(r.entries)
}

// Set a destination in the RIB. Returns true if the Advertisement might change.
func (r *Rib) Set(destName enc.Name, nextHop enc.Name, cost uint64) bool {
	destHash := destName.Hash()
	nextHopHash := nextHop.Hash()

	// Create RIB entry if it doesn't exist
	entry, ok := r.entries[destHash]
	if !ok {
		entry = &RibEntry{
			rib:   r,
			name:  destName.Clone(),
			costs: make(map[uint64]uint64),
		}
		r.entries[destHash] = entry
	}

	// Create neighbor link if it doesn't exist
	if _, ok := r.neighbors[nextHopHash]; !ok {
		r.neighbors[nextHopHash] = nextHop.Clone()
	}

	return entry.Set(nextHopHash, cost)
}

// Check if a destination is reachable in the RIB.
func (r *Rib) Has(destName enc.Name) bool {
	entry := r.entries[destName.Hash()]
	if entry == nil {
		return false
	}
	return entry.lowest1 < config.CostInfinity
}

// Get all destinations reachable in the RIB.
func (r *Rib) Entries() iter.Seq2[uint64, *RibEntry] {
	return func(yield func(uint64, *RibEntry) bool) {
		for hash, entry := range r.entries {
			if entry.lowest1 < config.CostInfinity {
				if !yield(hash, entry) {
					return
				}
			}
		}
	}
}

// Remove all entries with a given next hop.
// Returns true if the Advertisement might change.
func (r *Rib) RemoveNextHop(nextHop enc.Name) bool {
	nextHopHash := nextHop.Hash()
	dirty := false

	for _, entry := range r.entries {
		if _, ok := entry.costs[nextHopHash]; ok {
			delete(entry.costs, nextHopHash)
			dirty = entry.refresh() || dirty
		}
	}

	return dirty
}

// Resets all entries for a given next hop to infinity without
// refreshing any entry. This is specifically intended for the
// RIB update algorithm to avoid unnecessary changes.
func (r *Rib) DirtyResetNextHop(nextHop enc.Name) {
	nextHopHash := nextHop.Hash()
	for _, entry := range r.entries {
		entry.costs[nextHopHash] = config.CostInfinity
		entry.dirty = true
	}
}

// Whenever the RIB is changed, this must be called manually
// to remove unreachable destinations.
// Returns true if the Advertisement might change.
func (r *Rib) Prune() bool {
	dirty := false
	for _, entry := range r.entries {
		// Refresh entry if dirty
		if entry.dirty {
			dirty = entry.refresh() || dirty
		}

		// Remove if no valid next hops
		if entry.lowest1 == config.CostInfinity {
			delete(r.entries, entry.name.Hash())
			dirty = true
		}
	}
	return dirty
}

// Get all advertisement entries in the RIB.
func (r *Rib) Advert() *tlv.Advertisement {
	advert := &tlv.Advertisement{
		Entries: make([]*tlv.AdvEntry, 0, len(r.entries)),
	}

	for _, entry := range r.entries {
		advert.Entries = append(advert.Entries, &tlv.AdvEntry{
			Destination: &tlv.Destination{Name: entry.name},
			NextHop: &tlv.Destination{
				Name: r.neighbors[entry.nextHop1],
			},
			Cost:      entry.lowest1,
			OtherCost: entry.lowest2,
		})
	}

	return advert
}

// (AI GENERATED DESCRIPTION): Returns the name stored in this RIB entry.
func (e *RibEntry) Name() enc.Name {
	return e.name
}

// (AI GENERATED DESCRIPTION): Updates a RIB entry’s cost for a given next hop, refreshing the entry only if the cost changes, and returns whether a refresh was performed.
func (e *RibEntry) Set(nextHop uint64, cost uint64) bool {
	if known, ok := e.costs[nextHop]; !ok || known != cost {
		e.costs[nextHop] = cost
		return e.refresh()
	}

	// Prevent triggering an unnecessary refresh
	return false
}

// Update lowest and second lowest costs for the entry.
func (e *RibEntry) refresh() bool {
	e.dirty = false
	lowest1 := config.CostInfinity
	lowest2 := config.CostInfinity
	nextHop1 := uint64(0)
	nextHop2 := uint64(0)

	for hop, cost := range e.costs {
		if cost < lowest1 || (cost == lowest1 && hop < nextHop1) {
			lowest2 = lowest1
			nextHop2 = nextHop1
			lowest1 = cost
			nextHop1 = hop
		} else if cost < lowest2 || (cost == lowest2 && hop < nextHop2) {
			lowest2 = cost
			nextHop2 = hop
		}
	}

	if e.lowest1 != lowest1 || e.lowest2 != lowest2 || e.nextHop1 != nextHop1 || e.nextHop2 != nextHop2 {
		e.lowest1 = lowest1
		e.lowest2 = lowest2
		e.nextHop1 = nextHop1
		e.nextHop2 = nextHop2
		log.Info(e.rib, "Update next hop", "name", e.name,
			"hop1", e.rib.neighbors[nextHop1], "cost1", lowest1,
			"hop2", e.rib.neighbors[nextHop2], "cost2", lowest2)
		return true
	}

	return false
}
