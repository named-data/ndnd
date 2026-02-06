package pt

import (
	"sync"
	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/table"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	enc "github.com/named-data/ndnd/std/encoding"
	ndn_sync "github.com/named-data/ndnd/std/sync"
)

type PrefixDaemon struct {
	mu sync.Mutex
	pfx *PrefixTable
	pfxSvs *ndn_sync.SvsALO
	pfxSubs map[uint64]enc.Name
	callbackIndex uint64
	onChange map[uint64]func()
	routerName enc.Name
}

const PrefixSnapThreshold = 50

// note - config is currently from dv, this will be extracted into a PrefixTable-specific config
func NewPrefixDaemon(config *config.Config, objectClient ndn.Client) *PrefixDaemon {
	var ptable *PrefixTable

	// Subscription List
	pfxSubs := make(map[uint64]enc.Name)

	// SVS Delivery Agent for syncing prefix table across all NDN routers
	pfxSvs, err := ndn_sync.NewSvsALO(ndn_sync.SvsAloOpts{
		Name: config.RouterName(),
		Svs: ndn_sync.SvSyncOpts{
			Client:      objectClient,
			GroupPrefix: config.PrefixTableGroupPrefix(),
		},
		Snapshot: &ndn_sync.SnapshotNodeLatest{
			Client: objectClient,
			SnapMe: func(name enc.Name) (enc.Wire, error) {
				return ptable.Snap(), nil
			},
			Threshold: PrefixSnapThreshold,
		},
	})
	if err != nil {
		panic(err)
	}

	// Local Prefix Table
	ptable = NewPrefixTable(config, func(w enc.Wire) {
		if _, _, err := pfxSvs.Publish(w); err != nil {
			log.Error(ptable, "Failed to publish prefix table update", "err", err)
		}
	})

	return &PrefixDaemon{
		mu: sync.Mutex{},
		onChange: make(map[uint64]func()),
		callbackIndex: 0,
		pfx: ptable,
		pfxSvs: pfxSvs,
		pfxSubs: pfxSubs,
		routerName: config.RouterName(),
	}
}

func (pid *PrefixDaemon) Start() {
	pid.pfxSvs.Start()
	pid.pfx.Reset()
}

func (pid *PrefixDaemon) Stop() {
	pid.pfxSvs.Stop()
}

func (pid *PrefixDaemon) UpdateFromRib(rib *table.Rib) {
	pid.mu.Lock()
	defer pid.mu.Unlock()

	// Update svs subscriptions for new prefixes from RIB
	for hash, router := range rib.Entries() {
		if router.Name().Equal(pid.routerName) {
			continue
		}

		if _, ok := pid.pfxSubs[hash]; !ok {
			log.Info(pid.pfx, "Router is now reachable", "name", router.Name())
			pid.pfxSubs[hash] = router.Name()

			pid.pfxSvs.SubscribePublisher(router.Name(), func(sp ndn_sync.SvsPub) {
				pid.mu.Lock()
				defer pid.mu.Unlock()

				// Both snapshots and normal data are handled the same way
				if dirty := pid.pfx.Apply(sp.Content); dirty {
					// Trigger the callback for prefix table changes
					// Main callback triggered will update the local fib if prefix table changed
					// and is expensive
					for _, callback := range pid.onChange {
						go callback()
					}
				}
			})
		}
	}

	// Remove dead subscriptions
	for hash, name := range pid.pfxSubs {
		if !rib.Has(name) {
			log.Info(pid.pfx, "Router is now unreachable", "name", name)
			pid.pfxSvs.UnsubscribePublisher(name)
			delete(pid.pfxSubs, hash)
		}
	}
}

func (pid *PrefixDaemon) OnChange(callback func()) uint64 {
	pid.mu.Lock()
	defer pid.mu.Unlock()


	callbackIndex := pid.callbackIndex
	pid.onChange[callbackIndex] = callback
	pid.callbackIndex += 1
	return callbackIndex
}

func (pid *PrefixDaemon) RemoveOnChange(idx uint64) {
	pid.mu.Lock()
	defer pid.mu.Unlock()
	delete(pid.onChange, idx)
}
