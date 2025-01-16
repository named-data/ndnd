package table

import (
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/utils"
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

func NewNeighborTable(config *config.Config, nfdc *nfdc.NfdMgmtThread) *NeighborTable {
	return &NeighborTable{
		config:    config,
		nfdc:      nfdc,
		neighbors: make(map[uint64]*NeighborState),
	}
}

func (nt *NeighborTable) String() string {
	return "dv-neighbors"
}

func (nt *NeighborTable) Get(name enc.Name) *NeighborState {
	return nt.GetH(name.Hash())
}

func (nt *NeighborTable) GetH(nameHash uint64) *NeighborState {
	return nt.neighbors[nameHash]
}

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

func (nt *NeighborTable) Remove(name enc.Name) {
	hash := name.Hash()
	if ns := nt.GetH(hash); ns != nil {
		ns.delete()
	}
	delete(nt.neighbors, hash)
}

func (nt *NeighborTable) GetAll() []*NeighborState {
	neighbors := make([]*NeighborState, 0, len(nt.neighbors))
	for _, neighbor := range nt.neighbors {
		neighbors = append(neighbors, neighbor)
	}
	return neighbors
}

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

func (ns *NeighborState) localRoute() enc.Name {
	return enc.LOCALHOP.Append(ns.Name.Append(
		enc.NewStringComponent(enc.TypeKeywordNameComponent, "DV"),
	)...)
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
				FaceId: utils.IdPtr(faceId),
				Origin: utils.IdPtr(config.NlsrOrigin),
				Cost:   utils.IdPtr(uint64(0)),
			},
			Retries: 3,
		})
	}

	// For fetching advertisements from neighbor
	register(ns.localRoute())
	// Passive advertisement sync to neighbor
	register(ns.nt.config.AdvertisementSyncPassivePrefix())
	// For prefix table sync group
	register(ns.nt.config.PrefixTableSyncPrefix())
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
				FaceId: utils.IdPtr(ns.faceId),
				Origin: utils.IdPtr(config.NlsrOrigin),
			},
			Retries: 1,
		})
	}

	// Always remove local data route to neighbor
	unregister(ns.localRoute())

	// If there are multiple neighbors on this face, we do not
	// want to unregister the global routes to the face.
	for _, ons := range ns.nt.neighbors {
		if ons != ns && ons.faceId == ns.faceId {
			return // skip global unregistration
		}
	}

	unregister(ns.nt.config.AdvertisementSyncPassivePrefix())
	unregister(ns.nt.config.PrefixTableSyncPrefix())
}
