package dv

import (
	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
)

// Compute the RIB chnages for this neighbor
func (dv *Router) ribUpdate(ns *table.NeighborState) {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	if ns.Advert == nil {
		return
	}

	// TODO: use cost to neighbor
	localCost := uint64(1)

	// Trigger our own advertisement if needed
	var dirty bool = false

	// Reset destinations for this neighbor
	dv.rib.DirtyResetNextHop(ns.Name)

	for _, entry := range ns.Advert.Entries {
		// Use the advertised cost by default
		cost := entry.Cost + localCost

		// Poison reverse - try other cost if next hop is us
		if entry.NextHop.Name.Equal(dv.config.RouterName()) {
			if entry.OtherCost < config.CostInfinity {
				cost = entry.OtherCost + localCost
			} else {
				cost = config.CostInfinity
			}
		}

		// Skip unreachable destinations
		if cost >= config.CostInfinity {
			continue
		}

		// Check advertisement changes
		dirty = dv.rib.Set(entry.Destination.Name, ns.Name, cost) || dirty
	}

	// Drop dead entries
	dirty = dv.rib.Prune() || dirty

	// If advert changed, increment sequence number
	if dirty {
		go func() {
			dv.fibUpdate()
			dv.advert.generate()
			dv.prefixDataFetchAll()
		}()
	}
}

// Check for dead neighbors
func (dv *Router) checkDeadNeighbors() {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	dirty := false
	for _, ns := range dv.neighbors.GetAll() {
		// Check if the neighbor is entirely dead
		if ns.IsDead() {
			log.Info(dv, "Neighbor is dead", "router", ns.Name)

			// This is the ONLY place that can remove neighbors
			dv.neighbors.Remove(ns.Name)

			// Remove neighbor from RIB and prune
			dirty = dv.rib.RemoveNextHop(ns.Name) || dirty
			dirty = dv.rib.Prune() || dirty
		}
	}

	if dirty {
		go func() {
			dv.fibUpdate()
			dv.advert.generate()
		}()
	}
}

// Update the FIB
func (dv *Router) fibUpdate() {
	log.Debug(dv, "Sychronizing updates to forwarding table")

	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// Name prefixes from global prefix table as well as RIB
	names := make(map[uint64]enc.Name)
	fibEntries := make(map[uint64][]table.FibEntry)

	// Helper to add fib entries
	register := func(name enc.Name, fes []table.FibEntry) {
		nameH := name.Hash()
		names[nameH] = name
		fibEntries[nameH] = append(fibEntries[nameH], fes...)
	}

	// Update paths to all routers from RIB
	for _, router := range dv.rib.Entries() {
		routerName := router.Name()

		// Skip if this is us
		if routerName.Equal(dv.config.RouterName()) {
			continue
		}

		// Get FIB entry to reach this router
		fes := dv.rib.GetFibEntries(dv.neighbors, routerName.Hash())

		// Add entry to the router itself
		routerPrefix := routerName.Append(enc.NewStringComponent(enc.TypeKeywordNameComponent, "DV"))
		register(routerPrefix, fes)

		// Add entries to all prefixes announced by this router
		for _, prefix := range dv.pfx.GetRouter(routerName).Prefixes {
			// Use the same nexthop entries as the exit router itself
			// De-duplication is done by the fib table update function
			register(prefix.Name, fes)
		}
	}

	// Update all FIB entries to NFD
	dv.fib.UnmarkAll()
	for nameH, fes := range fibEntries {
		if dv.fib.UpdateH(nameH, names[nameH], fes) {
			dv.fib.MarkH(nameH)
		}
	}
	dv.fib.RemoveUnmarked()
}
