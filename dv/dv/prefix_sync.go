package dv

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/object"
	ndn_sync "github.com/named-data/ndnd/std/sync"
)

// Fetch all required prefix data
func (dv *Router) prefixDataFetchAll() {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	for _, e := range dv.rib.Entries() {
		router := dv.pfx.GetRouter(e.Name())
		if router != nil && router.Known < router.Latest {
			dv.prefixDataFetch(e.Name())
		}
	}
}

// Received prefix sync update
func (dv *Router) onPfxSyncUpdate(ssu ndn_sync.SvSyncUpdate) {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// Update the prefix table
	r := dv.pfx.GetRouter(ssu.Name)
	if ssu.Boot > r.BootTime {
		r.BootTime = ssu.Boot
		r.Known = 0 // new boot
	} else if ssu.Boot < r.BootTime {
		return // old update
	}
	r.Latest = ssu.High

	// Start a fetching thread (if needed)
	dv.prefixDataFetch(ssu.Name)
}

// Fetch prefix data (call with lock held)
func (dv *Router) prefixDataFetch(nName enc.Name) {
	// Check if the RIB has this destination
	if !dv.rib.Has(nName) {
		return
	}

	// At any given time, there is only one thread fetching
	// prefix data for a node. This thread recursively calls itself.
	router := dv.pfx.GetRouter(nName)
	if router == nil || router.Fetching || router.Known >= router.Latest {
		return
	}
	router.Fetching = true

	// Fetch the prefix data object
	log.Debug(dv.pfx, "Fetching prefix data", "router", nName, "known", router.Known, "latest", router.Latest)

	name := router.GetNextDataName()
	dv.client.Consume(name, func(state *object.ConsumeState) bool {
		if !state.IsComplete() {
			return true
		}

		go func() {
			fetchErr := state.Error()
			if fetchErr != nil {
				log.Warn(dv.pfx, "Failed to fetch prefix data", "name", state.Name(), "err", fetchErr)
				time.Sleep(1 * time.Second) // wait on error
			}

			dv.mutex.Lock()
			defer dv.mutex.Unlock()

			// Process the prefix data on success
			if fetchErr == nil && dv.pfx.ApplyData(state.Name(), state.Content(), router) {
				// Update the local fib if prefix table changed
				go dv.fibUpdate() // very expensive
			}

			// Done fetching, restart if needed
			router.Fetching = false
			dv.prefixDataFetch(nName)
		}()

		return true
	})
}
