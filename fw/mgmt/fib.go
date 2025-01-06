/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
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
	"github.com/named-data/ndnd/std/utils"
)

// FIBModule is the module that handles FIB Management.
type FIBModule struct {
	manager *Thread
}

func (f *FIBModule) String() string {
	return "FIBMgmt"
}

func (f *FIBModule) registerManager(manager *Thread) {
	f.manager = manager
}

func (f *FIBModule) getManager() *Thread {
	return f.manager
}

func (f *FIBModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.LogWarn(f, "Received FIB management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[len(LOCAL_PREFIX)+1].String()
	switch verb {
	case "add-nexthop":
		f.add(interest)
	case "remove-nexthop":
		f.remove(interest)
	case "list":
		f.list(interest)
	default:
		f.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

func (f *FIBModule) add(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(f, interest)
	if params == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}

	faceID := *interest.inFace
	if params.FaceId != nil && *params.FaceId != 0 {
		faceID = *params.FaceId
		if face.FaceTable.Get(faceID) == nil {
			f.manager.sendCtrlResp(interest, 410, "Face does not exist", nil)
			return
		}
	}

	cost := uint64(0)
	if params.Cost != nil {
		cost = *params.Cost
	}
	table.FibStrategyTable.InsertNextHopEnc(params.Name, faceID, cost)

	core.LogInfo(f, "Created nexthop for ", params.Name, " to FaceID=", faceID, "with Cost=", cost)

	f.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		FaceId: utils.IdPtr(faceID),
		Cost:   utils.IdPtr(cost),
	})
}

func (f *FIBModule) remove(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(f, interest)
	if params == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}

	faceID := *interest.inFace
	if params.FaceId != nil && *params.FaceId != 0 {
		faceID = *params.FaceId
	}
	table.FibStrategyTable.RemoveNextHopEnc(params.Name, faceID)

	core.LogInfo(f, "Removed nexthop for ", params.Name, " to FaceID=", faceID)

	f.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:   params.Name,
		FaceId: utils.IdPtr(faceID),
	})
}

func (f *FIBModule) list(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	// TODO: For thread safety, we should lock the FIB from writes until we are done
	entries := table.FibStrategyTable.GetAllFIBEntries()
	dataset := &mgmt.FibStatus{}
	for _, fsEntry := range entries {
		nextHops := fsEntry.GetNextHops()
		fibEntry := &mgmt.FibEntry{
			Name:           fsEntry.Name(),
			NextHopRecords: make([]*mgmt.NextHopRecord, len(nextHops)),
		}
		for i, nexthop := range nextHops {
			fibEntry.NextHopRecords[i] = &mgmt.NextHopRecord{
				FaceId: nexthop.Nexthop,
				Cost:   nexthop.Cost,
			}
		}

		dataset.Entries = append(dataset.Entries, fibEntry)
	}

	name := LOCAL_PREFIX.Append(
		enc.NewStringComponent(enc.TypeGenericNameComponent, "fib"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "list"),
	)
	f.manager.sendStatusDataset(interest, name, dataset.Encode())
}
