package pt

import (
	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	enc "github.com/named-data/ndnd/std/encoding"
	ndn_sync "github.com/named-data/ndnd/std/sync"
)

type PrefixDaemon struct {
	pfx *PrefixTable
	pfxSvs *ndn_sync.SvsALO
	pfxSubs map[uint64]enc.Name
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
		pfx: ptable,
		pfxSvs: pfxSvs,
		pfxSubs: pfxSubs,
	}
}
