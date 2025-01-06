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
			go dv.prefixDataFetch(e.Name())
		}
	}
}

// Received prefix sync update
func (dv *Router) onPfxSyncUpdate(ssu ndn_sync.SvSyncUpdate) {
	// Update the prefix table
	dv.mutex.Lock()
	dv.pfx.GetRouter(ssu.NodeId).Latest = ssu.High
	dv.mutex.Unlock()

	// Start a fetching thread (if needed)
	dv.prefixDataFetch(ssu.NodeId)
}

// Fetch prefix data
func (dv *Router) prefixDataFetch(nodeId enc.Name) {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// Check if the RIB has this destination
	if !dv.rib.Has(nodeId) {
		return
	}

	// At any given time, there is only one thread fetching
	// prefix data for a node. This thread recursively calls itself.
	router := dv.pfx.GetRouter(nodeId)
	if router == nil || router.Fetching || router.Known >= router.Latest {
		return
	}
	router.Fetching = true

	// Fetch the prefix data object
	log.Debugf("prefix-table: fetching object for %s [%d => %d]", nodeId, router.Known, router.Latest)

	name := router.GetNextDataName()
	dv.client.Consume(name, func(state *object.ConsumeState) bool {
		if !state.IsComplete() {
			return true
		}

		go func() {
			fetchErr := state.Error()
			if fetchErr != nil {
				log.Warnf("prefix-table: failed to fetch object %s: %+v", state.Name(), fetchErr)
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
			go dv.prefixDataFetch(nodeId)
		}()

		return true
	})
}
