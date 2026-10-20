package dv

import (
	"math"
	"testing"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/table"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/stretchr/testify/require"
)

// An advertisement entry with Cost = MaxUint64 must stay unreachable.
// updateRib adds the local link cost without checking for overflow, so
// MaxUint64 + 1 wraps to 0 and the route is accepted with the best
// possible cost.
func TestUpdateRibOverflowAdvertisedCost(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network = "/ndn"
	cfg.Router = "/ndn/router1"
	cfg.KeyChainUri = "insecure"
	require.NoError(t, cfg.Parse())

	dv := &Router{config: cfg, rib: table.NewRib(cfg)}

	dest, err := enc.NameFromStr("/ndn/evil")
	require.NoError(t, err)
	nbr, err := enc.NameFromStr("/ndn/router2")
	require.NoError(t, err)

	ns := &table.NeighborState{
		Name: nbr,
		Advert: &tlv.Advertisement{Entries: []*tlv.AdvEntry{{
			Destination: &tlv.Destination{Name: dest},
			NextHop:     &tlv.Destination{Name: nbr},
			Cost:        math.MaxUint64,
		}}},
	}

	dv.updateRib(ns)

	// Block the post-update goroutine before it touches uninitialised state
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// The route must be unreachable, not cost 0
	require.False(t, dv.rib.Has(dest))
}
