package table

import (
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

type NeighborTable struct {
	// main DV config
	config *config.Config
	// nfd management thread
	nfdc *nfdc.NfdMgmtThread
	// neighbor name hash -> neighbor
	neighbors map[uint64]*NeighborState
}

type NeighborState struct {
	// pointer to the neighbor table
	nt *NeighborTable

	// neighbor name
	Name enc.Name
	// advertisement boot time for neighbor
	AdvertBoot uint64
	// advertisement sequence number for neighbor
	AdvertSeq uint64
	// most recent advertisement
	Advert *tlv.Advertisement

	// time of last sync interest
	lastSeen time.Time
	// latest known face ID
	faceId uint64
	// the received advertisement is active face
	isFaceActive bool
}

// (AI GENERATED DESCRIPTION): Creates a new NeighborTable instance with the supplied configuration and NFD client, initializing an empty map to store neighbor states.
func NewNeighborTable(config *config.Config, nfdc *nfdc.NfdMgmtThread) *NeighborTable {
	return &NeighborTable{
		config:    config,
		nfdc:      nfdc,
		neighbors: make(map[uint64]*NeighborState),
	}
}

// (AI GENERATED DESCRIPTION): Returns the constant string `"dv-neighbors"`, serving as the identifier for a `NeighborTable` instance.
func (nt *NeighborTable) String() string {
	return "dv-neighbors"
}

// (AI GENERATED DESCRIPTION): Returns the number of neighbors currently stored in the NeighborTable.
func (nt *NeighborTable) Size() int {
	return len(nt.neighbors)
}

// (AI GENERATED DESCRIPTION): Retrieves the NeighborState corresponding to the given name by hashing the name and looking up the resulting key.
func (nt *NeighborTable) Get(name enc.Name) *NeighborState {
	return nt.GetH(name.Hash())
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the `NeighborState` stored in the `NeighborTable` for the specified `nameHash`.
func (nt *NeighborTable) GetH(nameHash uint64) *NeighborState {
	return nt.neighbors[nameHash]
}

// (AI GENERATED DESCRIPTION): Adds a new neighbor with the given name to the table, initializing its state (sequence, advert, face ID, and last seen time) and storing it in the neighbors map.
func (nt *NeighborTable) Add(name enc.Name) *NeighborState {
	neighbor := &NeighborState{
		nt: nt,

		Name:      name.Clone(),
		AdvertSeq: 0,
		Advert:    nil,

		lastSeen: time.Now(),
		faceId:   0,
	}
	nt.neighbors[name.Hash()] = neighbor
	return neighbor
}

// (AI GENERATED DESCRIPTION): Removes the neighbor entry identified by the given name from the NeighborTable, performing any necessary cleanup on its state before deleting it from the internal map.
func (nt *NeighborTable) Remove(name enc.Name) {
	hash := name.Hash()
	if ns := nt.GetH(hash); ns != nil {
		ns.delete()
	}
	delete(nt.neighbors, hash)
}

// (AI GENERATED DESCRIPTION): Returns a slice containing all neighbor states currently stored in the table.
func (nt *NeighborTable) GetAll() []*NeighborState {
	neighbors := make([]*NeighborState, 0, len(nt.neighbors))
	for _, neighbor := range nt.neighbors {
		neighbors = append(neighbors, neighbor)
	}
	return neighbors
}

// (AI GENERATED DESCRIPTION): Determines whether a neighbor is considered dead by comparing the time elapsed since its last seen timestamp to the router’s configured dead interval.
func (ns *NeighborState) IsDead() bool {
	return time.Since(ns.lastSeen) > ns.nt.config.RouterDeadInterval()
}

// Call this when a ping is received from a face.
// This will automatically register the face route with the neighbor
// and update the last seen time for the neighbor.
// Return => true if the face ID has changed
func (ns *NeighborState) RecvPing(faceId uint64, active bool) (error, bool) {
	if ns.isFaceActive && !active {
		// This ping is passive, but we already have an active ping.
		return nil, false // ignore this ping.
	}

	// Update last seen time for neighbor
	// Note that we skip this when the face is active and the ping is passive.
	// This is because we want to detect if the active face is removed.
	ns.lastSeen = time.Now()

	// If face ID has changed, re-register face.
	if ns.faceId != faceId {
		ns.isFaceActive = active
		log.Info(ns.nt, "Neighbor face change", "neighbor", ns.Name, "faceid", faceId, "old", ns.faceId)
		ns.routeUnregister()
		ns.routeRegister(faceId)
		return nil, true
	}

	return nil, false
}

// Called when the neighbor is removed from the neighbor table.
func (ns *NeighborState) delete() {
	ns.routeUnregister()
	ns.Advert = nil
	ns.faceId = 0
	ns.isFaceActive = false
}

// (AI GENERATED DESCRIPTION): Creates the local route name for a neighbor by prefixing the neighbor’s name with the `LOCALHOP` namespace and appending the “DV” keyword component.
func (ns *NeighborState) localRoute() enc.Name {
	return enc.LOCALHOP.
		Append(ns.Name...).
		Append(enc.NewKeywordComponent("DV"))
}

// Register route to this neighbor
func (ns *NeighborState) routeRegister(faceId uint64) {
	ns.faceId = faceId

	register := func(route enc.Name) {
		ns.nt.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "register",
			Args: &mgmt.ControlArgs{
				Name:   route,
				FaceId: optional.Some(faceId),
				Origin: optional.Some(config.NlsrOrigin),
				Cost:   optional.Some(uint64(0)),
			},
			Retries: 3,
		})
	}

	// For fetching advertisements from neighbor
	register(ns.localRoute())
	// Passive advertisement sync to neighbor
	register(ns.nt.config.AdvertisementSyncPassivePrefix())
	// For prefix table sync group
	register(ns.nt.config.PrefixTableGroupPrefix().
		Append(enc.NewKeywordComponent("svs")))
}

// Single attempt to unregister the route
func (ns *NeighborState) routeUnregister() {
	if ns.faceId == 0 {
		return // not set
	}

	unregister := func(route enc.Name) {
		ns.nt.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "unregister",
			Args: &mgmt.ControlArgs{
				Name:   route,
				FaceId: optional.Some(ns.faceId),
				Origin: optional.Some(config.NlsrOrigin),
			},
			Retries: 1,
		})
	}

	// Always remove local data routes to neighbor
	unregister(ns.localRoute())

	// If there are multiple neighbors on this face, we do not
	// want to unregister the global routes to the face.
	for _, ons := range ns.nt.neighbors {
		if ons != ns && ons.faceId == ns.faceId {
			return // skip global unregistration
		}
	}

	unregister(ns.nt.config.AdvertisementSyncPassivePrefix())
	unregister(ns.nt.config.PrefixTableGroupPrefix().
		Append(enc.NewKeywordComponent("svs")))
}
