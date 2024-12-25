/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"strconv"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/face"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/utils"
)

// RIBModule is the module that handles RIB Management.
type RIBModule struct {
	manager               *Thread
	nextRIBDatasetVersion uint64
}

func (r *RIBModule) String() string {
	return "RIBMgmt"
}

func (r *RIBModule) registerManager(manager *Thread) {
	r.manager = manager
}

func (r *RIBModule) getManager() *Thread {
	return r.manager
}

func (r *RIBModule) handleIncomingInterest(interest ndn.Interest, pitToken []byte, inFace uint64) {
	// Dispatch by verb
	verb := interest.Name()[r.manager.prefixLength()+1].String()
	switch verb {
	case "register":
		r.register(interest, pitToken, inFace)
	case "unregister":
		r.unregister(interest, pitToken, inFace)
	case "announce":
		r.announce(interest, pitToken, inFace)
	case "list":
		r.list(interest, pitToken, inFace)
	default:
		core.LogWarn(r, "Received Interest for non-existent verb '", verb, "'")
		response := makeControlResponse(501, "Unknown verb", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}
}

func (r *RIBModule) register(interest ndn.Interest, pitToken []byte, inFace uint64) {
	var response *mgmt.ControlResponse

	if len(interest.Name()) < r.manager.prefixLength()+3 {
		// Name not long enough to contain ControlParameters
		core.LogWarn(r, "Missing ControlParameters in ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	params := decodeControlParameters(r, interest)
	if params == nil {
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	if params.Name == nil {
		core.LogWarn(r, "Missing Name in ControlParameters for ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	faceID := inFace
	if params.FaceId != nil && *params.FaceId != 0 {
		faceID = *params.FaceId
		if face.FaceTable.Get(faceID) == nil {
			response = makeControlResponse(410, "Face does not exist", nil)
			r.manager.sendResponse(response, interest, pitToken, inFace)
			return
		}
	}

	origin := table.RouteOriginApp
	if params.Origin != nil {
		origin = *params.Origin
	}

	cost := uint64(0)
	if params.Cost != nil {
		cost = *params.Cost
	}

	flags := table.RouteFlagChildInherit
	if params.Flags != nil {
		flags = *params.Flags
	}

	expirationPeriod := (*time.Duration)(nil)
	if params.ExpirationPeriod != nil {
		expirationPeriod = new(time.Duration)
		*expirationPeriod = time.Duration(*params.ExpirationPeriod) * time.Millisecond
	}

	table.Rib.AddEncRoute(params.Name, &table.Route{
		FaceID:           faceID,
		Origin:           origin,
		Cost:             cost,
		Flags:            flags,
		ExpirationPeriod: expirationPeriod,
	})
	if expirationPeriod != nil {
		core.LogInfo(r, "Created route for Prefix=", params.Name, ", FaceID=", faceID, ", Origin=", origin,
			", Cost=", cost, ", Flags=0x", strconv.FormatUint(flags, 16), ", ExpirationPeriod=", expirationPeriod)
	} else {
		core.LogInfo(r, "Created route for Prefix=", params.Name, ", FaceID=", faceID, ", Origin=", origin,
			", Cost=", cost, ", Flags=0x", strconv.FormatUint(flags, 16))
	}
	responseParams := map[string]any{
		"Name":   params.Name,
		"FaceId": faceID,
		"Origin": origin,
		"Cost":   cost,
		"Flags":  flags,
	}
	if expirationPeriod != nil {
		responseParams["ExpirationPeriod"] = uint64(expirationPeriod.Milliseconds())
	}
	response = makeControlResponse(200, "OK", responseParams)
	r.manager.sendResponse(response, interest, pitToken, inFace)
}

func (r *RIBModule) unregister(interest ndn.Interest, pitToken []byte, inFace uint64) {
	var response *mgmt.ControlResponse

	if len(interest.Name()) < r.manager.prefixLength()+3 {
		// Name not long enough to contain ControlParameters
		core.LogWarn(r, "Missing ControlParameters in ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	params := decodeControlParameters(r, interest)
	if params == nil {
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	if params.Name == nil {
		core.LogWarn(r, "Missing Name in ControlParameters for ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	faceID := inFace
	if params.FaceId != nil && *params.FaceId != 0 {
		faceID = *params.FaceId
	}

	origin := table.RouteOriginApp
	if params.Origin != nil {
		origin = *params.Origin
	}
	table.Rib.RemoveRouteEnc(params.Name, faceID, origin)

	core.LogInfo(r, "Removed route for Prefix=", params.Name, ", FaceID=", faceID, ", Origin=", origin)
	responseParams := map[string]any{
		"Name":   params.Name,
		"FaceId": faceID,
		"Origin": origin,
	}
	response = makeControlResponse(200, "OK", responseParams)
	r.manager.sendResponse(response, interest, pitToken, inFace)
}

func (r *RIBModule) announce(interest ndn.Interest, pitToken []byte, inFace uint64) {
	var response *mgmt.ControlResponse
	if len(interest.Name()) != r.manager.prefixLength()+3 ||
		interest.Name()[r.manager.prefixLength()+2].Typ != enc.TypeParametersSha256DigestComponent {
		// Name not long enough to contain ControlParameters
		core.LogWarn(r, "Name of Interest=", interest.Name(),
			" is either too short or incorrectly formatted to be rib/announce")
		response = makeControlResponse(400, "Name is incorrect", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	// Get PrefixAnnouncement
	appParam := interest.AppParam()
	if appParam.Length() == 0 {
		core.LogWarn(r, "PrefixAnnouncement Interest=", interest.Name(), " missing PrefixAnnouncement")
		response = makeControlResponse(400, "PrefixAnnouncement is missing", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	data, _, err := spec.Spec{}.ReadData(enc.NewWireReader(appParam))
	if err != nil {
		core.LogWarn(r, "PrefixAnnouncement Interest=", interest.Name(), " has invalid PrefixAnnouncement")
		response = makeControlResponse(400, "PrefixAnnouncement is invalid", nil)
		r.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}
	if data != nil {
	}

	core.LogError(r, "YaNFD does not support PrefixAnnouncement")
	response = makeControlResponse(501, "YaNFD does not support PrefixAnnouncement", nil)
	r.manager.sendResponse(response, interest, pitToken, inFace)
}

func (r *RIBModule) list(interest ndn.Interest, pitToken []byte, _ uint64) {
	if len(interest.Name()) > r.manager.prefixLength()+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	entries := table.Rib.GetAllEntries()
	dataset := &mgmt.RibStatus{}
	for _, entry := range entries {
		ribEntry := &mgmt.RibEntry{
			Name:   entry.Name,
			Routes: make([]*mgmt.Route, len(entry.GetRoutes())),
		}
		for i, route := range entry.GetRoutes() {
			ribEntry.Routes[i] = &mgmt.Route{}
			ribEntry.Routes[i].FaceId = route.FaceID
			ribEntry.Routes[i].Origin = route.Origin
			ribEntry.Routes[i].Cost = route.Cost
			ribEntry.Routes[i].Flags = route.Flags
			if route.ExpirationPeriod != nil {
				ribEntry.Routes[i].ExpirationPeriod = utils.IdPtr(uint64(*route.ExpirationPeriod / time.Millisecond))
			}
		}

		dataset.Entries = append(dataset.Entries, ribEntry)
	}

	name, _ := enc.NameFromStr(interest.Name()[:r.manager.prefixLength()].String() + "/rib/list")
	segments := makeStatusDataset(name, r.nextRIBDatasetVersion, dataset.Encode())
	r.manager.transport.Send(segments, pitToken, nil)
	core.LogTrace(r, "Published RIB dataset version=", r.nextRIBDatasetVersion,
		", containing ", len(segments), " segments")
	r.nextRIBDatasetVersion++
}
