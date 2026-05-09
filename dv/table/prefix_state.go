package table

import (
	"slices"
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

type PrefixState struct {
	config  *config.Config
	publish func(enc.Wire)
	routers map[uint64]*PrefixStateRouter
	me      *PrefixStateRouter
}

type PrefixStateRouter struct {
	Name     enc.Name
	Prefixes map[string]*PrefixEntry
}

type PrefixEntry struct {
	Name enc.Name
	// Default to false
	Multicast bool
	// ValidityPeriod from prefix inserter side, optional.
	ValidityPeriod *spec.ValidityPeriod
	// Only known for the local router when inserted via face-aware APIs.
	NextHops []PrefixNextHop
}

type PrefixSnapshotEntry struct {
	Router         enc.Name
	Name           enc.Name
	Multicast      bool
	ValidityPeriod *spec.ValidityPeriod
	NextHops       []PrefixNextHop
}

type ExpiredPrefix struct {
	Router enc.Name
	Name   enc.Name
}

type PrefixNextHop struct {
	Face uint64
	Cost uint64
}

// NewPrefixState creates the local prefix state table.
func NewPrefixState(config *config.Config, publish func(enc.Wire)) *PrefixState {
	pt := &PrefixState{
		config:  config,
		publish: publish,
		routers: make(map[uint64]*PrefixStateRouter),
		me:      nil,
	}
	pt.me = pt.GetRouter(config.RouterName())
	return pt
}

func (pt *PrefixState) String() string {
	return "prefix-state"
}

// GetRouter returns the state for a router, creating it if needed.
func (pt *PrefixState) GetRouter(name enc.Name) *PrefixStateRouter {
	hash := name.Hash()
	router := pt.routers[hash]
	if router == nil {
		router = &PrefixStateRouter{
			Name:     name.Clone(),
			Prefixes: make(map[string]*PrefixEntry),
		}
		pt.routers[hash] = router
	}
	return router
}

func (pt *PrefixState) Reset() {
	log.Info(pt, "Reset table")
	clear(pt.me.Prefixes)

	op := tlv.PrefixOpList{
		EgressRouter:  &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpReset: true,
	}
	pt.publish(op.Encode())
}

// Announce updates or creates a local prefix with an optional validity period.
// Use face=0 and cost=0 for route-only semantics.
// multicast=true marks this as a Sync group prefix (vs. a producer prefix).
func (pt *PrefixState) Announce(name enc.Name, face uint64, cost uint64, multicast bool, validity *spec.ValidityPeriod) {
	hash := name.TlvStr()
	entry := pt.me.Prefixes[hash]
	publishAdd := false
	if entry == nil {
		entry = &PrefixEntry{
			Name:      name,
			Multicast: multicast,
		}
		pt.me.Prefixes[hash] = entry
		publishAdd = true
	} else if multicast && !entry.Multicast {
		entry.Multicast = true
		publishAdd = true
	}

	if !sameValidityPeriod(entry.ValidityPeriod, validity) {
		entry.ValidityPeriod = cloneValidityPeriod(validity)
		publishAdd = true
	}

	if face == 0 && cost == 0 {
		log.Info(pt, "Local announce", "name", name)
		// Route-only announcements should not retain local face/cost state.
		entry.NextHops = nil
	} else {
		log.Info(pt, "Local announce", "name", name, "face", face, "cost", cost)
		nexthop := PrefixNextHop{
			Face: face,
			Cost: cost,
		}

		found := false
		for i, nh := range entry.NextHops {
			if nh.Face == face {
				found = true
				entry.NextHops[i] = nexthop
				break
			}
		}
		if !found {
			entry.NextHops = append(entry.NextHops, nexthop)
		}
	}

	if publishAdd {
		pt.publishAdd(hash)
	}
}

// Withdraw removes a local next hop and removes the prefix when no next hops remain.
func (pt *PrefixState) Withdraw(name enc.Name, face uint64) {
	if face == 0 {
		log.Info(pt, "Local withdraw", "name", name)
		hash := name.TlvStr()

		entry := pt.me.Prefixes[hash]
		if entry == nil {
			return
		}

		pt.publishRemoveEntry(entry)
		delete(pt.me.Prefixes, hash)
		return
	}

	log.Info(pt, "Local withdraw", "name", name, "face", face)
	hash := name.TlvStr()

	// Check if entry does not exist
	entry := pt.me.Prefixes[hash]
	if entry == nil {
		return
	}

	// Remove nexthop from entry
	for i, nh := range entry.NextHops {
		if nh.Face == face {
			entry.NextHops = slices.Delete(entry.NextHops, i, i+1)
			break
		}
	}

	if len(entry.NextHops) < 1 {
		// remove the entry and publish right away
		pt.publishRemoveEntry(entry)
		delete(pt.me.Prefixes, hash)
	}
}

// Publishes the update to the network.
func (pt *PrefixState) publishAdd(hash string) {
	entry := pt.me.Prefixes[hash]
	if entry == nil {
		return // never
	}
	log.Info(pt, "Global announce", "name", entry.Name)
	op := tlv.PrefixOpList{
		EgressRouter: &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpAdds: []*tlv.PrefixOpAdd{{
			Name:           entry.Name,
			Multicast:      entry.Multicast,
			ValidityPeriod: cloneValidityPeriod(entry.ValidityPeriod),
		}},
	}
	pt.publish(op.Encode())
}

func (pt *PrefixState) publishRemoveEntry(entry *PrefixEntry) {
	if entry == nil {
		return // never
	}
	log.Info(pt, "Global withdraw", "name", entry.Name)
	op := tlv.PrefixOpList{
		EgressRouter:    &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpRemoves: []*tlv.PrefixOpRemove{{Name: entry.Name}},
	}
	pt.publish(op.Encode())
}

// Applies ops from a list. Returns if dirty.
func (pt *PrefixState) Apply(wire enc.Wire) (dirty bool) {
	ops, err := tlv.ParsePrefixOpList(enc.NewWireView(wire), true)
	if err != nil {
		log.Warn(pt, "Failed to parse PrefixOpList", "err", err)
		return false
	}

	if ops.EgressRouter == nil || len(ops.EgressRouter.Name) == 0 {
		log.Error(pt, "Received PrefixOpList has no ExitRouter")
		return false
	}

	router := pt.GetRouter(ops.EgressRouter.Name)

	if ops.PrefixOpReset {
		log.Info(pt, "Reset remote prefixes", "router", ops.EgressRouter.Name)
		router.Prefixes = make(map[string]*PrefixEntry)
		dirty = true
	}

	for _, add := range ops.PrefixOpAdds {
		log.Info(pt, "Add remote prefix", "router", ops.EgressRouter.Name, "name", add.Name, "multicast", add.Multicast)
		router.Prefixes[add.Name.TlvStr()] = &PrefixEntry{
			Name:           add.Name.Clone(),
			Multicast:      add.Multicast,
			ValidityPeriod: cloneValidityPeriod(add.ValidityPeriod),
		}
		dirty = true
	}

	for _, remove := range ops.PrefixOpRemoves {
		log.Info(pt, "Remove remote prefix", "router", ops.EgressRouter.Name, "name", remove.Name)
		delete(router.Prefixes, remove.Name.TlvStr())
		dirty = true
	}

	return dirty
}

func (pt *PrefixState) Snap() enc.Wire {
	snap := tlv.PrefixOpList{
		EgressRouter:  &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpReset: true,
		PrefixOpAdds:  make([]*tlv.PrefixOpAdd, 0, len(pt.me.Prefixes)),
	}

	for _, entry := range pt.me.Prefixes {
		snap.PrefixOpAdds = append(snap.PrefixOpAdds, &tlv.PrefixOpAdd{
			Name:           entry.Name,
			Multicast:      entry.Multicast,
			ValidityPeriod: cloneValidityPeriod(entry.ValidityPeriod),
		})
	}

	return snap.Encode()
}

// SnapshotEntries returns a point-in-time copy of all known prefix entries.
func (pt *PrefixState) SnapshotEntries() []PrefixSnapshotEntry {
	entries := make([]PrefixSnapshotEntry, 0)
	for _, router := range pt.routers {
		for _, entry := range router.Prefixes {
			nextHops := make([]PrefixNextHop, len(entry.NextHops))
			copy(nextHops, entry.NextHops)
			entries = append(entries, PrefixSnapshotEntry{
				Router:         router.Name.Clone(),
				Name:           entry.Name.Clone(),
				Multicast:      entry.Multicast,
				ValidityPeriod: cloneValidityPeriod(entry.ValidityPeriod),
				NextHops:       nextHops,
			})
		}
	}
	return entries
}

// EntryCount returns total prefix entries across all known routers in PSD.
func (pt *PrefixState) EntryCount() int {
	count := 0
	for _, router := range pt.routers {
		count += len(router.Prefixes)
	}
	return count
}

// IsValidAt returns true if the prefix is currently within its validity window.
func (entry *PrefixEntry) IsValidAt(now time.Time) bool {
	if entry.ValidityPeriod == nil {
		return true
	}

	if entry.ValidityPeriod.NotBefore != "" {
		if notBefore, err := time.Parse(spec.TimeFmt, entry.ValidityPeriod.NotBefore); err == nil && now.Before(notBefore) {
			return false
		}
	}
	if entry.ValidityPeriod.NotAfter != "" {
		if notAfter, err := time.Parse(spec.TimeFmt, entry.ValidityPeriod.NotAfter); err == nil && now.After(notAfter) {
			return false
		}
	}
	return true
}

// PruneExpired removes expired prefix entries and returns removed tuples.
// For local entries, corresponding remove updates are also published.
func (pt *PrefixState) PruneExpired(now time.Time) (expired []ExpiredPrefix, dirty bool) {
	expired = make([]ExpiredPrefix, 0)

	for _, router := range pt.routers {
		for key, entry := range router.Prefixes {
			if entry.IsValidAt(now) {
				continue
			}

			if router == pt.me {
				pt.publishRemoveEntry(entry)
			}
			delete(router.Prefixes, key)
			expired = append(expired, ExpiredPrefix{
				Router: router.Name.Clone(),
				Name:   entry.Name.Clone(),
			})
			dirty = true
		}
	}

	return expired, dirty
}

func cloneValidityPeriod(validity *spec.ValidityPeriod) *spec.ValidityPeriod {
	if validity == nil {
		return nil
	}
	return &spec.ValidityPeriod{
		NotBefore: validity.NotBefore,
		NotAfter:  validity.NotAfter,
	}
}

func sameValidityPeriod(a, b *spec.ValidityPeriod) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.NotBefore == b.NotBefore && a.NotAfter == b.NotAfter
}
