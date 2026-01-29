package dv

import (
	"fmt"
	"time"

	"github.com/named-data/ndnd/dv/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/types/optional"
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
	objDir *storage.MemoryFifoDir
}

// (AI GENERATED DESCRIPTION): Returns a constant string “dv‑advert” identifying this advert module.
func (a *advertModule) String() string {
	return "dv-advert"
}

// (AI GENERATED DESCRIPTION): Sends sync interests for both active (outgoing) and passive (incoming) connections, logging any errors that occur.
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

// (AI GENERATED DESCRIPTION): Sends a signed state‑vector Data packet as the payload of a sync Interest to the given `syncName`, expressing the Interest locally without expecting a reply.
func (a *advertModule) sendSyncInterestImpl(syncName enc.Name) (err error) {
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

	// Sign the Sync Data
	dataName := a.dv.config.AdvertisementDataPrefix().
		Append(enc.NewKeywordComponent("SYNC"))
	signer := a.dv.client.SuggestSigner(dataName)
	if signer == nil {
		return fmt.Errorf("no signer found for %s", dataName)
	}

	// Make Data packet
	dataCfg := &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeBlob),
	}
	data, err := a.dv.engine.Spec().MakeData(dataName, dataCfg, sv.Encode(), signer)
	if err != nil {
		log.Error(nil, "Failed make data", "err", err)
		return
	}

	// Make SVS Sync Interest
	intCfg := &ndn.InterestConfig{
		Lifetime: optional.Some(1 * time.Second),
		Nonce:    utils.ConvertNonce(a.dv.engine.Timer().Nonce()),
		HopLimit: utils.IdPtr(byte(2)), // use localhop w/ this
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

// (AI GENERATED DESCRIPTION): Handles an incoming Sync Interest by verifying its signature, decoding the included state vector, and invoking the state‑vector processing routine.
func (a *advertModule) OnSyncInterest(args ndn.InterestHandlerArgs, active bool) {
	// If there is no incoming face ID, we can't use this
	if !args.IncomingFaceId.IsSet() {
		log.Warn(a, "Received Sync Interest with no incoming face ID, ignoring")
		return
	}

	// Check if app param is present
	if args.Interest.AppParam() == nil {
		log.Warn(a, "Received Sync Interest with no AppParam, ignoring")
		return
	}

	// Decode Sync Data
	data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(args.Interest.AppParam()))
	if err != nil {
		log.Warn(a, "Failed to parse Sync Data", "err", err)
		return
	}

	// Validate signature
	a.dv.client.ValidateExt(ndn.ValidateExtArgs{
		Data:        data,
		SigCovered:  sigCov,
		CertNextHop: args.IncomingFaceId,
		Callback: func(valid bool, err error) {
			if !valid || err != nil {
				log.Warn(a, "Failed to validate advert broadcast",
					"name", data.Name(), "valid", valid, "err", err)
				return
			}

			// Decode state vector
			svWire := data.Content()
			params, err := spec_svs.ParseSvsData(enc.NewWireView(svWire), false)
			if err != nil || params.StateVector == nil {
				log.Warn(a, "Failed to parse StateVec", "err", err)
				return
			}

			// Process the state vector
			go a.onStateVector(params.StateVector, args.IncomingFaceId.Unwrap(), active)
		},
	})
}

// (AI GENERATED DESCRIPTION): Processes a received StateVector, updates neighbor states and timestamps, schedules a data fetch for each new or updated neighbor, and triggers a Forwarding Information Base refresh if any neighbor’s face changed.
func (a *advertModule) onStateVector(sv *spec_svs.StateVector, faceId uint64, active bool) {
	// Process each entry in the state vector
	a.dv.mutex.Lock()
	defer a.dv.mutex.Unlock()

	// FIB needs update if face changes for any neighbor
	fibDirty := false
	markRecvPing := func(ns *table.NeighborState) {
		err, faceDirty := ns.RecvPing(faceId, active)
		if err != nil {
			log.Warn(a, "Failed to update neighbor", "err", err)
		}
		fibDirty = fibDirty || faceDirty
	}

	// There should only be one entry in the StateVector, but check all anyway
	for _, node := range sv.Entries {
		if len(node.SeqNoEntries) != 1 {
			log.Warn(a, "Unexpected SeqNoEntries count", "count", len(node.SeqNoEntries), "router", node.Name)
			return
		}
		entry := node.SeqNoEntries[0]

		// Parse name from entry
		if node.Name == nil {
			log.Warn(a, "Failed to parse neighbor name")
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

		time.AfterFunc(10*time.Millisecond, func() { // debounce
			a.dataFetch(node.Name, entry.BootstrapTime, entry.SeqNo)
		})
	}

	// Update FIB if needed
	if fibDirty {
		go a.dv.updateFib()
	}
}
