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

// PIBModule is the module that handles PIB Management.
type PIBModule struct {
	manager *Thread
}

// (AI GENERATED DESCRIPTION): Returns the identifier string "mgmt-pib" that represents the PIB module’s name.
func (p *PIBModule) String() string {
	return "mgmt-pib"
}

// (AI GENERATED DESCRIPTION): Registers the given Thread as the manager for this PIBModule by setting its manager field.
func (p *PIBModule) registerManager(manager *Thread) {
	p.manager = manager
}

// (AI GENERATED DESCRIPTION): Returns the Thread manager associated with the PIBModule.
func (p *PIBModule) getManager() *Thread {
	return p.manager
}

// (AI GENERATED DESCRIPTION): Handles locally-issued PIB management Interests by dispatching to the requested verb.
func (p *PIBModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.Log.Warn(p, "Received PIB management Interest from non-local source - DROP")
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

func (p *PIBModule) addEgress(interest *Interest) {
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

	table.Pib.AddEgressEnc(params.Name, params.Egress.Name)
	core.Log.Info(p, "Added PIB egress", "name", params.Name, "egress", params.Egress.Name)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		Egress: params.Egress,
	})
}

func (p *PIBModule) removeEgress(interest *Interest) {
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

	table.Pib.RemoveEgressEnc(params.Name, params.Egress.Name)
	core.Log.Info(p, "Removed PIB egress", "name", params.Name, "egress", params.Egress.Name)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		Egress: params.Egress,
	})
}

func (p *PIBModule) addNextHop(interest *Interest) {
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
	table.Pib.AddNextHopEnc(params.Name, faceID, cost)

	core.Log.Info(p, "Added PIB nexthop", "name", params.Name, "faceid", faceID, "cost", cost)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		FaceId: optional.Some(faceID),
		Cost:   optional.Some(cost),
	})
}

func (p *PIBModule) removeNextHop(interest *Interest) {
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
	table.Pib.RemoveNextHopEnc(params.Name, faceID)

	core.Log.Info(p, "Removed PIB nexthop", "name", params.Name, "faceid", faceID)

	p.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		FaceId: optional.Some(faceID),
	})
}

func (p *PIBModule) list(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	entries := table.Pib.GetAllEntries()
	dataset := &mgmt.PibStatus{}
	for _, entry := range entries {
		pibEntry := &mgmt.PibEntry{
			Name:           entry.Name,
			EgressRecords:  make([]*mgmt.EgressRecord, 0, len(entry.EgressRouters)),
			NextHopRecords: make([]*mgmt.NextHopRecord, 0, len(entry.NextHops)),
		}

		for _, egress := range entry.EgressRouters {
			pibEntry.EgressRecords = append(pibEntry.EgressRecords, &mgmt.EgressRecord{
				Name: egress,
			})
		}
		for _, nh := range entry.NextHops {
			pibEntry.NextHopRecords = append(pibEntry.NextHopRecords, &mgmt.NextHopRecord{
				FaceId: nh.FaceID,
				Cost:   nh.Cost,
			})
		}

		dataset.Entries = append(dataset.Entries, pibEntry)
	}

	name := LOCAL_PREFIX.
		Append(enc.NewGenericComponent("pib")).
		Append(enc.NewGenericComponent("list"))
	p.manager.sendStatusDataset(interest, name, dataset.Encode())
}
