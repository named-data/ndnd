/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2026 Eric Newberry, Tianyuan Yu.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/face"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

// PETModule is the module that handles Prefix Egress Table (PET) management.
type PETModule struct {
	manager *Thread
}

func newPETModule() *PETModule {
	return &PETModule{}
}

func (p *PETModule) String() string {
	return "mgmt-pet"
}

func (p *PETModule) registerManager(manager *Thread) {
	p.manager = manager
}

func (p *PETModule) getManager() *Thread {
	return p.manager
}

func (p *PETModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.Log.Warn(p, "Received PET management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[len(LOCAL_PREFIX)+1].String()
	switch verb {
	case "add-egress":
		p.addEgress(interest)
	case "remove-egress":
		p.removeEgress(interest)
	case "add-nexthop":
		p.addNextHop(interest)
	case "remove-nexthop":
		p.removeNextHop(interest)
	case "list":
		p.list(interest)
	default:
		p.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

func (p *PETModule) addEgress(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(p, interest)
	if params == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}
	if params.Egress == nil || len(params.Egress.Name) == 0 {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Egress)", nil)
		return
	}

	multicast := params.Multicast
	table.Pet.AddEgressEnc(params.Name, params.Egress.Name, multicast)
	core.Log.Info(p, "Added PET egress", "name", params.Name, "egress", params.Egress.Name, "multicast", multicast)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		Egress: params.Egress,
	})
}

func (p *PETModule) removeEgress(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(p, interest)
	if params == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}
	if params.Egress == nil || len(params.Egress.Name) == 0 {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Egress)", nil)
		return
	}

	table.Pet.RemoveEgressEnc(params.Name, params.Egress.Name)
	core.Log.Info(p, "Removed PET egress", "name", params.Name, "egress", params.Egress.Name)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		Egress: params.Egress,
	})
}

func (p *PETModule) addNextHop(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(p, interest)
	if params == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}

	faceID := interest.inFace.Unwrap()
	if fid, ok := params.FaceId.Get(); ok && fid != 0 {
		faceID = fid
		if face.FaceTable.Get(faceID) == nil {
			p.manager.sendCtrlResp(interest, 410, "Face does not exist", nil)
			return
		}
	}

	cost := params.Cost.GetOr(0)
	table.Pet.AddNextHopEnc(params.Name, faceID, cost)

	core.Log.Info(p, "Added PET nexthop", "name", params.Name, "faceid", faceID, "cost", cost)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		FaceId: optional.Some(faceID),
		Cost:   optional.Some(cost),
	})
}

func (p *PETModule) removeNextHop(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(p, interest)
	if params == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		p.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}

	faceID := interest.inFace.Unwrap()
	if fid, ok := params.FaceId.Get(); ok && fid != 0 {
		faceID = fid
	}
	table.Pet.RemoveNextHopEnc(params.Name, faceID)

	core.Log.Info(p, "Removed PET nexthop", "name", params.Name, "faceid", faceID)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		FaceId: optional.Some(faceID),
	})
}

func (p *PETModule) list(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	entries := table.Pet.GetAllEntries()
	dataset := &mgmt.PetStatus{}
	for _, entry := range entries {
		petEntry := &mgmt.PetEntry{
			Name:           entry.Name,
			EgressRecords:  make([]*mgmt.EgressRecord, 0, len(entry.EgressRouters)),
			NextHopRecords: make([]*mgmt.NextHopRecord, 0, len(entry.NextHops)),
			Multicast:      entry.Multicast,
		}

		for _, egress := range entry.EgressRouters {
			petEntry.EgressRecords = append(petEntry.EgressRecords, &mgmt.EgressRecord{
				Name: egress,
			})
		}
		for _, nh := range entry.NextHops {
			petEntry.NextHopRecords = append(petEntry.NextHopRecords, &mgmt.NextHopRecord{
				FaceId: nh.FaceID,
				Cost:   nh.Cost,
			})
		}

		dataset.Entries = append(dataset.Entries, petEntry)
	}

	name := LOCAL_PREFIX.
		Append(enc.NewGenericComponent("pet")).
		Append(enc.NewGenericComponent("list"))
	p.manager.sendStatusDataset(interest, name, dataset.Encode())
}
