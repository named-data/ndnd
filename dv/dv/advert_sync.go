package dv

import (
	"time"

	"github.com/named-data/ndnd/dv/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
	"github.com/named-data/ndnd/std/object"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
)

type advertModule struct {
	// parent router
	dv *Router
	// advertisement boot time for self
	bootTime uint64
	// advertisement sequence number for self
	seq uint64
	// object directory for advertisement data
	objDir *object.MemoryFifoDir
}

func (a *advertModule) String() string {
	return "dv-advert"
}

func (a *advertModule) sendSyncInterest() (err error) {
	// Sync Interests for our outgoing connections
	err = a.sendSyncInterestImpl(a.dv.config.AdvertisementSyncActivePrefix())
	if err != nil {
		log.Error(a, "Failed to send active sync interest", "err", err)
	}

	// Sync Interests for incoming connections
	err = a.sendSyncInterestImpl(a.dv.config.AdvertisementSyncPassivePrefix())
	if err != nil {
		log.Error(a, "Failed to send passive sync interest", "err", err)
	}

	return err
}

func (a *advertModule) sendSyncInterestImpl(prefix enc.Name) (err error) {
	// SVS v3 Sync Data
	syncName := prefix.Append(enc.NewVersionComponent(3))

	// State Vector for our group
	sv := &spec_svs.SvsData{
		StateVector: &spec_svs.StateVector{
			Entries: []*spec_svs.StateVectorEntry{{
				Name: a.dv.config.RouterName(),
				SeqNoEntries: []*spec_svs.SeqNoEntry{{
					BootstrapTime: a.bootTime,
					SeqNo:         a.seq,
				}},
			}},
		},
	}

	// TODO: sign the sync data
	signer := sec.NewSha256Signer()

	dataCfg := &ndn.DataConfig{
		ContentType: utils.IdPtr(ndn.ContentTypeBlob),
	}
	data, err := a.dv.engine.Spec().MakeData(syncName, dataCfg, sv.Encode(), signer)
	if err != nil {
		log.Error(nil, "Failed make data", "err", err)
		return
	}

	// Make SVS Sync Interest
	intCfg := &ndn.InterestConfig{
		Lifetime: utils.IdPtr(1 * time.Second),
		Nonce:    utils.ConvertNonce(a.dv.engine.Timer().Nonce()),
		HopLimit: utils.IdPtr(uint(2)), // use localhop w/ this
	}
	interest, err := a.dv.engine.Spec().MakeInterest(syncName, intCfg, data.Wire, nil)
	if err != nil {
		return err
	}

	// Sync Interest has no reply
	err = a.dv.engine.Express(interest, nil)
	if err != nil {
		return err
	}

	return nil
}

func (a *advertModule) OnSyncInterest(args ndn.InterestHandlerArgs, active bool) {
	// If there is no incoming face ID, we can't use this
	if args.IncomingFaceId == nil {
		log.Warn(a, "Received Sync Interest with no incoming face ID, ignoring")
		return
	}

	// Check if app param is present
	if args.Interest.AppParam() == nil {
		log.Warn(a, "Received Sync Interest with no AppParam, ignoring")
		return
	}

	// Decode Sync Data
	pkt, _, err := spec.ReadPacket(enc.NewWireReader(args.Interest.AppParam()))
	if err != nil {
		log.Warn(a, "Failed to parse Sync Data", "err", err)
		return
	}
	if pkt.Data == nil {
		log.Warn(a, "No Sync Data, ignoring")
		return
	}

	// TODO: verify signature on Sync Interest

	// Decode state vector
	svWire := pkt.Data.Content()
	params, err := spec_svs.ParseSvsData(enc.NewWireReader(svWire), false)
	if err != nil || params.StateVector == nil {
		log.Warn(a, "Failed to parse StateVec", "err", err)
		return
	}

	// Process each entry in the state vector
	a.dv.mutex.Lock()
	defer a.dv.mutex.Unlock()

	// FIB needs update if face changes for any neighbor
	fibDirty := false
	markRecvPing := func(ns *table.NeighborState) {
		err, faceDirty := ns.RecvPing(*args.IncomingFaceId, active)
		if err != nil {
			log.Warn(a, "Failed to update neighbor", "err", err)
		}
		fibDirty = fibDirty || faceDirty
	}

	// There should only be one entry in the StateVector, but check all anyway
	for _, node := range params.StateVector.Entries {
		if len(node.SeqNoEntries) != 1 {
			log.Warn(a, "Unexpected SeqNoEntries count", "count", len(node.SeqNoEntries), "router", node.Name)
			return
		}
		entry := node.SeqNoEntries[0]

		// Parse name from entry
		if node.Name == nil {
			log.Warn(a, "Failed to parse neighbor name", "err", err)
			continue
		}

		// Check if the entry is newer than what we know
		ns := a.dv.neighbors.Get(node.Name)
		if ns != nil {
			if ns.AdvertBoot >= entry.BootstrapTime && ns.AdvertSeq >= entry.SeqNo {
				// Nothing has changed, skip
				markRecvPing(ns)
				continue
			}
		} else {
			// Create new neighbor entry cause none found
			// This is the ONLY place where neighbors are created
			// In all other places, quit if not found
			ns = a.dv.neighbors.Add(node.Name)
		}

		markRecvPing(ns)
		ns.AdvertBoot = entry.BootstrapTime
		ns.AdvertSeq = entry.SeqNo

		go a.dataFetch(node.Name, entry.BootstrapTime, entry.SeqNo)
	}

	// Update FIB if needed
	if fibDirty {
		go a.dv.fibUpdate()
	}
}
