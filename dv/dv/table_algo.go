package dv

import (
	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/sync"
)

// postUpdateRib should be called after the RIB has been updated.
// It triggers a corresponding fib update and advert generation.
// Run it in a separate goroutine to avoid deadlocks.
func (dv *Router) postUpdateRib() {
	dv.updateFib()
	dv.advert.generate()
	dv.updatePrefixSubs()
}

// updateRib computes the RIB chnages for this neighbor
func (dv *Router) updateRib(ns *table.NeighborState) {
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
		go dv.postUpdateRib()
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
		go dv.postUpdateRib()
	}
}

// updateFib synchronizes the FIB with the RIB.
func (dv *Router) updateFib() {
	log.Debug(dv, "Sychronizing updates to forwarding table")

	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// Name prefixes from global prefix table as well as RIB
	names := make(map[uint64]enc.Name)
	fibEntries := make(map[uint64][]table.FibEntry)

	// Helper to add fib entries
	register := func(name enc.Name, fes []table.FibEntry, cost uint64) {
		nameH := name.Hash()
		names[nameH] = name

		// Append to existing entries with new cost
		for _, fe := range fes { // fe byval
			fe.Cost += cost
			fibEntries[nameH] = append(fibEntries[nameH], fe)
		}
	}

	// Update paths to all routers from RIB
	for hash, router := range dv.rib.Entries() {
		// Skip if this is us
		if router.Name().Equal(dv.config.RouterName()) {
			continue
		}

		// Get FIB entry to reach this router
		fes := dv.rib.GetFibEntries(dv.neighbors, hash)

		// Add entry for the router's prefix sync group prefix
		proute := dv.config.PrefixTableGroupPrefix().
			Append(router.Name()...)
		register(proute, fes, 0)

		// Add entries to all prefixes announced by this router
		for _, prefix := range dv.pfx.GetRouter(router.Name()).Prefixes {
			// Use the same nexthop entries as the exit router itself
			// De-duplication is done by the fib table update function
			register(prefix.Name, fes, prefix.Cost)
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

// updatePrefixSubs updates the prefix table subscriptions
func (dv *Router) updatePrefixSubs() {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// Get all prefixes from the RIB
	for hash, router := range dv.rib.Entries() {
		if router.Name().Equal(dv.config.RouterName()) {
			continue
		}

		if _, ok := dv.pfxSubs[hash]; !ok {
			log.Info(dv, "Router is now reachable", "name", router.Name())
			dv.pfxSubs[hash] = router.Name()

			dv.pfxSvs.SubscribePublisher(router.Name(), func(sp sync.SvsPub) {
				dv.mutex.Lock()
				defer dv.mutex.Unlock()

				// Both snapshots and normal data are handled the same way
				if dirty := dv.pfx.Apply(sp.Content); dirty {
					// Update the local fib if prefix table changed
					go dv.updateFib() // expensive
				}
			})
		}
	}

	// Remove dead subscriptions
	for hash, name := range dv.pfxSubs {
		if !dv.rib.Has(name) {
			log.Info(dv, "Router is now unreachable", "name", name)
			dv.pfxSvs.UnsubscribePublisher(name)
			delete(dv.pfxSubs, hash)
		}
	}
}
