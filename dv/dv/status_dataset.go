package dv

import (
	"slices"
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
	"github.com/named-data/ndnd/std/utils"
)

func (dv *Router) routingStatus() *tlv.RoutingStatus {
	snapshot := dv.copyRoutingStatus()
	for _, router := range snapshot.Routers {
		slices.SortFunc(router.Prefixes, func(a, b *tlv.PrefixOpAdd) int { return a.Name.Compare(b.Name) })
	}
	slices.SortFunc(snapshot.Routers, func(a, b *tlv.RouterStatus) int { return a.Name.Compare(b.Name) })
	return snapshot
}

// Copy names and values while locked; sorting and encoding use only the copy.
func (dv *Router) copyRoutingStatus() *tlv.RoutingStatus {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	snapshot := &tlv.RoutingStatus{Status: &tlv.Status{
		Version:     utils.NDNdVersion,
		NetworkName: &tlv.Destination{Name: dv.config.NetworkName().Clone()},
		RouterName:  &tlv.Destination{Name: dv.config.RouterName().Clone()},
		NRibEntries: uint64(dv.rib.Size()), NNeighbors: uint64(dv.neighbors.Size()), NFibEntries: uint64(dv.fib.Size()),
	}}
	for _, route := range dv.rib.Advert().Entries {
		if route.Cost >= config.CostInfinity {
			continue
		}
		router := &tlv.RouterStatus{
			Name: route.Destination.Name.Clone(), Cost: route.Cost,
			NextHop: &tlv.Destination{Name: route.NextHop.Name.Clone()},
		}
		for _, prefix := range dv.pfx.GetRouter(router.Name).Prefixes {
			router.Prefixes = append(router.Prefixes, &tlv.PrefixOpAdd{Name: prefix.Name.Clone(), Cost: prefix.Cost})
		}
		snapshot.Routers = append(snapshot.Routers, router)
	}
	return snapshot
}

func (dv *Router) onStatusDataset(args ndn.InterestHandlerArgs) {
	prefix := config.StatusDatasetPrefix(dv.config.RouterName())
	name := args.Interest.Name()
	discovery := args.Interest.CanBePrefix() && (name.Equal(prefix) ||
		name.Equal(prefix.Append(enc.NewKeywordComponent(rdr.MetadataKeyword))))
	if !discovery || !dv.statusMu.TryLock() {
		dv.replyStatusDataset(args)
		return
	}
	// At most one publisher runs, outside the engine loop. Existing segments
	// remain readable while a new snapshot is copied, signed, and stored.
	go func() {
		defer dv.statusMu.Unlock()
		if dv.statusUpdated.IsZero() || time.Since(dv.statusUpdated) >= time.Second {
			now := time.Now()
			versioned := prefix.WithVersion(utils.MakeTimestamp(now))
			_, err := dv.client.Produce(ndn.ProduceArgs{
				Name: versioned, Content: dv.routingStatus().Encode(), FreshnessPeriod: time.Second,
			})
			if err != nil {
				log.Warn(dv, "Failed to publish routing status dataset", "err", err)
				return
			}
			dv.statusObjects.Push(versioned)
			if err := dv.statusObjects.Evict(dv.client); err != nil {
				log.Warn(dv, "Failed to evict routing status dataset", "err", err)
			}
			dv.statusUpdated = now
		}
		dv.replyStatusDataset(args)
	}()
}

func (dv *Router) replyStatusDataset(args ndn.InterestHandlerArgs) {
	name := args.Interest.Name()
	packet, err := dv.client.Store().Get(name, args.Interest.CanBePrefix())
	if err != nil || packet == nil {
		return
	}
	if err := args.Reply(enc.Wire{packet}); err != nil {
		log.Debug(dv, "Failed to reply with routing status dataset", "err", err)
	}
}
