/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2022 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"math"
	"net"
	"sort"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/face"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/utils"
)

// FaceModule is the module that handles Face Management.
type FaceModule struct {
	manager *Thread
}

func (f *FaceModule) String() string {
	return "FaceMgmt"
}

func (f *FaceModule) registerManager(manager *Thread) {
	f.manager = manager
}

func (f *FaceModule) getManager() *Thread {
	return f.manager
}

func (f *FaceModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.LogWarn(f, "Received face management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[len(LOCAL_PREFIX)+1].String()
	switch verb {
	case "create":
		f.create(interest)
	case "update":
		f.update(interest)
	case "destroy":
		f.destroy(interest)
	case "list":
		f.list(interest)
	case "query":
		f.query(interest)
	default:
		core.LogWarn(f, "Received Interest for non-existent verb '", verb, "'")
		f.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

func (f *FaceModule) create(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(f, interest)
	if params == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Uri == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	URI := defn.DecodeURIString(*params.Uri)
	if URI == nil || URI.Canonize() != nil {
		f.manager.sendCtrlResp(interest, 400, "URI could not be canonized", nil)
		return
	}

	if (params.Flags != nil && params.Mask == nil) || (params.Flags == nil && params.Mask != nil) {
		f.manager.sendCtrlResp(interest, 409, "Incomplete Flags/Mask combination", nil)
		return
	}

	// Ensure does not conflict with existing face
	existingFace := face.FaceTable.GetByURI(URI)
	if existingFace != nil {
		core.LogWarn(f, "Cannot create face ", URI, ": Conflicts with existing face FaceID=",
			existingFace.FaceID(), ", RemoteURI=", existingFace.RemoteURI())
		responseParams := &mgmt.ControlArgs{}
		f.fillFaceProperties(responseParams, existingFace)
		f.manager.sendCtrlResp(interest, 409, "Conflicts with existing face", responseParams)
		return
	}

	var linkService *face.NDNLPLinkService

	if URI.Scheme() == "udp4" || URI.Scheme() == "udp6" {
		// Validate that remote endpoint is an IP address
		remoteAddr := net.ParseIP(URI.Path())
		if remoteAddr == nil {
			f.manager.sendCtrlResp(interest, 406, "URI must be IP", nil)
			return
		}

		// Validate that remote endpoint is a unicast address
		if !(remoteAddr.IsGlobalUnicast() || remoteAddr.IsLinkLocalUnicast() || remoteAddr.IsLoopback()) {
			f.manager.sendCtrlResp(interest, 406, "URI must be unicast", nil)
			return
		}

		// Check face persistency
		persistency := mgmt.PersistencyPersistent
		if params.FacePersistency != nil && (*params.FacePersistency == uint64(mgmt.PersistencyPersistent) ||
			*params.FacePersistency == uint64(mgmt.PersistencyPermanent)) {
			persistency = mgmt.Persistency(*params.FacePersistency)
		} else if params.FacePersistency != nil {
			f.manager.sendCtrlResp(interest, 406, "Unacceptable persistency", nil)
			return
		}

		// Check congestion control
		baseCongestionMarkingInterval := 100 * time.Millisecond
		if params.BaseCongestionMarkInterval != nil {
			baseCongestionMarkingInterval = time.Duration(*params.BaseCongestionMarkInterval) * time.Nanosecond
		}

		defaultCongestionThresholdBytes := uint64(math.Pow(2, 16))
		if params.DefaultCongestionThreshold != nil {
			defaultCongestionThresholdBytes = *params.DefaultCongestionThreshold
		}

		// Create new UDP face
		transport, err := face.MakeUnicastUDPTransport(URI, nil, persistency)
		if err != nil {
			core.LogWarn(f, "Unable to create unicast UDP face with URI ", URI, ": ", err.Error())
			f.manager.sendCtrlResp(interest, 406, "Transport error", nil)
			return
		}

		if params.Mtu != nil {
			mtu := int(*params.Mtu)
			if *params.Mtu > defn.MaxNDNPacketSize {
				mtu = defn.MaxNDNPacketSize
			}
			transport.SetMTU(mtu)
		}

		// NDNLP link service parameters
		options := face.MakeNDNLPLinkServiceOptions()
		if params.Flags != nil {
			// Mask already guaranteed to be present if Flags is above
			flags := *params.Flags
			mask := *params.Mask

			if mask&face.FaceFlagLocalFields > 0 {
				// LocalFieldsEnabled
				if flags&face.FaceFlagLocalFields > 0 {
					options.IsConsumerControlledForwardingEnabled = true
					options.IsIncomingFaceIndicationEnabled = true
					options.IsLocalCachePolicyEnabled = true
				} else {
					options.IsConsumerControlledForwardingEnabled = false
					options.IsIncomingFaceIndicationEnabled = false
					options.IsLocalCachePolicyEnabled = false
				}
			}

			// Congestion control
			if mask&face.FaceFlagCongestionMarking > 0 {
				// CongestionMarkingEnabled
				options.IsCongestionMarkingEnabled = flags&face.FaceFlagCongestionMarking > 0
			}
			options.BaseCongestionMarkingInterval = baseCongestionMarkingInterval
			options.DefaultCongestionThresholdBytes = defaultCongestionThresholdBytes
		}

		linkService = face.MakeNDNLPLinkService(transport, options)
		linkService.Run(nil)
	} else if URI.Scheme() == "tcp4" || URI.Scheme() == "tcp6" {
		// Validate that remote endpoint is an IP address
		remoteAddr := net.ParseIP(URI.Path())
		if remoteAddr == nil {
			f.manager.sendCtrlResp(interest, 406, "URI must be IP", nil)
			return
		}

		// Validate that remote endpoint is a unicast address
		if !(remoteAddr.IsGlobalUnicast() || remoteAddr.IsLinkLocalUnicast() || remoteAddr.IsLoopback()) {
			f.manager.sendCtrlResp(interest, 406, "URI must be unicast", nil)
			return
		}

		// Check face persistency
		persistency := mgmt.PersistencyPersistent
		if params.FacePersistency != nil && (*params.FacePersistency == uint64(mgmt.PersistencyPersistent) ||
			*params.FacePersistency == uint64(mgmt.PersistencyPermanent)) {
			persistency = mgmt.Persistency(*params.FacePersistency)
		} else if params.FacePersistency != nil {
			f.manager.sendCtrlResp(interest, 406, "Unacceptable persistency", nil)
			return
		}

		// Check congestion control
		baseCongestionMarkingInterval := 100 * time.Millisecond
		if params.BaseCongestionMarkInterval != nil {
			baseCongestionMarkingInterval = time.Duration(*params.BaseCongestionMarkInterval) * time.Nanosecond
		}

		defaultCongestionThresholdBytes := uint64(math.Pow(2, 16))
		if params.DefaultCongestionThreshold != nil {
			defaultCongestionThresholdBytes = *params.DefaultCongestionThreshold
		}

		// Create new TCP face
		transport, err := face.MakeUnicastTCPTransport(URI, nil, persistency)
		if err != nil {
			core.LogWarn(f, "Unable to create unicast TCP face with URI ", URI, ":", err.Error())
			f.manager.sendCtrlResp(interest, 406, "Transport error", nil)
			return
		}

		if params.Mtu != nil {
			mtu := int(*params.Mtu)
			if *params.Mtu > defn.MaxNDNPacketSize {
				mtu = defn.MaxNDNPacketSize
			}
			transport.SetMTU(mtu)
		}

		// NDNLP link service parameters
		options := face.MakeNDNLPLinkServiceOptions()
		options.IsFragmentationEnabled = false // reliable stream
		if params.Flags != nil {
			// Mask already guaranteed to be present if Flags is above
			flags := *params.Flags
			mask := *params.Mask

			if mask&face.FaceFlagLocalFields > 0 {
				// LocalFieldsEnabled
				if flags&face.FaceFlagLocalFields > 0 {
					options.IsConsumerControlledForwardingEnabled = true
					options.IsIncomingFaceIndicationEnabled = true
					options.IsLocalCachePolicyEnabled = true
				} else {
					options.IsConsumerControlledForwardingEnabled = false
					options.IsIncomingFaceIndicationEnabled = false
					options.IsLocalCachePolicyEnabled = false
				}
			}

			// Congestion control
			if mask&face.FaceFlagCongestionMarking > 0 {
				// CongestionMarkingEnabled
				options.IsCongestionMarkingEnabled = flags&face.FaceFlagCongestionMarking > 0
			}
			options.BaseCongestionMarkingInterval = baseCongestionMarkingInterval
			options.DefaultCongestionThresholdBytes = defaultCongestionThresholdBytes
		}

		linkService = face.MakeNDNLPLinkService(transport, options)
		linkService.Run(nil)
	} else {
		f.manager.sendCtrlResp(interest, 406, "Unsupported scheme "+URI.Scheme(), nil)
		return
	}

	if linkService == nil { // Internal failure
		core.LogWarn(f, "Transport error when creating face ", URI)
		f.manager.sendCtrlResp(interest, 504, "Transport error when creating face", nil)
		return
	}

	responseParams := &mgmt.ControlArgs{}
	f.fillFaceProperties(responseParams, linkService)
	f.manager.sendCtrlResp(interest, 200, "OK", responseParams)

	core.LogInfo(f, "Created face with URI ", URI)
}

func (f *FaceModule) update(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(f, interest)
	if params == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	faceID := *interest.inFace
	if params.FaceId != nil && *params.FaceId != 0 {
		faceID = *params.FaceId
	}

	// Validate parameters
	responseParams := &mgmt.ControlArgs{}
	areParamsValid := true

	selectedFace := face.FaceTable.Get(faceID)
	if selectedFace == nil {
		core.LogWarn(f, "Cannot update specified (or implicit) FaceID=", faceID, " because it does not exist")
		f.manager.sendCtrlResp(interest, 404, "Face does not exist", &mgmt.ControlArgs{FaceId: utils.IdPtr(faceID)})
		return
	}

	// Can't update null (or internal) faces via management
	if selectedFace.RemoteURI().Scheme() == "null" || selectedFace.RemoteURI().Scheme() == "internal" {
		f.manager.sendCtrlResp(interest, 401, "Face cannot be updated via management", &mgmt.ControlArgs{FaceId: utils.IdPtr(faceID)})
		return
	}

	if params.FacePersistency != nil {
		if selectedFace.RemoteURI().Scheme() == "ether" && *params.FacePersistency != uint64(mgmt.PersistencyPermanent) {
			responseParams.FacePersistency = params.FacePersistency
			areParamsValid = false
		} else if (selectedFace.RemoteURI().Scheme() == "udp4" || selectedFace.RemoteURI().Scheme() == "udp6") &&
			*params.FacePersistency != uint64(mgmt.PersistencyPersistent) &&
			*params.FacePersistency != uint64(mgmt.PersistencyPermanent) {
			responseParams.FacePersistency = params.FacePersistency
			areParamsValid = false
		} else if selectedFace.LocalURI().Scheme() == "unix" &&
			*params.FacePersistency != uint64(mgmt.PersistencyPersistent) {
			responseParams.FacePersistency = params.FacePersistency
			areParamsValid = false
		}
	}

	if (params.Flags != nil && params.Mask == nil) || (params.Flags == nil && params.Mask != nil) {
		if params.Flags != nil {
			responseParams.Flags = params.Flags
		}
		if params.Mask != nil {
			responseParams.Mask = params.Mask
		}
		areParamsValid = false
	}

	if !areParamsValid {
		f.manager.sendCtrlResp(interest, 409, "ControlParameters are incorrect", responseParams)
		return
	}

	// Actually perform face updates

	// Persistency
	if params.FacePersistency != nil {
		// Correctness of FacePersistency already validated
		selectedFace.SetPersistency(mgmt.Persistency(*params.FacePersistency))
	}

	// Set NDNLP link service options
	if lpLinkService := selectedFace.(*face.NDNLPLinkService); lpLinkService != nil {
		options := lpLinkService.Options()

		// Congestion
		if params.BaseCongestionMarkInterval != nil &&
			time.Duration(*params.BaseCongestionMarkInterval)*time.Nanosecond != options.BaseCongestionMarkingInterval {
			options.BaseCongestionMarkingInterval = time.Duration(*params.BaseCongestionMarkInterval) * time.Nanosecond
			core.LogInfo(f, "FaceID=", faceID, ", BaseCongestionMarkingInterval=", options.BaseCongestionMarkingInterval)
		}

		if params.DefaultCongestionThreshold != nil &&
			*params.DefaultCongestionThreshold != options.DefaultCongestionThresholdBytes {
			options.DefaultCongestionThresholdBytes = *params.DefaultCongestionThreshold
			core.LogInfo(f, "FaceID=", faceID, ", DefaultCongestionThreshold=", options.DefaultCongestionThresholdBytes, "B")
		}

		// MTU
		if params.Mtu != nil {
			oldMTU := selectedFace.MTU()
			newMTU := min(int(*params.Mtu), defn.MaxNDNPacketSize)
			selectedFace.SetMTU(newMTU)
			core.LogInfo(f, "FaceID=", faceID, ", MTU ", oldMTU, " -> ", newMTU)
		}

		// Flags
		if params.Mask != nil && params.Flags != nil {
			flags := *params.Flags
			mask := *params.Mask

			if mask&face.FaceFlagLocalFields > 0 {
				if flags&face.FaceFlagLocalFields > 0 {
					core.LogInfo(f, "FaceID=", faceID, ", Enabling local fields")
					options.IsConsumerControlledForwardingEnabled = true
					options.IsIncomingFaceIndicationEnabled = true
					options.IsLocalCachePolicyEnabled = true
				} else {
					core.LogInfo(f, "FaceID=", faceID, ", Disabling local fields")
					options.IsConsumerControlledForwardingEnabled = false
					options.IsIncomingFaceIndicationEnabled = false
					options.IsLocalCachePolicyEnabled = false
				}
			}

			if mask&face.FaceFlagCongestionMarking > 0 {
				options.IsCongestionMarkingEnabled = flags&face.FaceFlagCongestionMarking > 0
				if flags&face.FaceFlagCongestionMarking > 0 {
					core.LogInfo(f, "FaceID=", faceID, ", Enabling congestion marking")
				} else {
					core.LogInfo(f, "FaceID=", faceID, ", Disabling congestion marking")
				}
			}
		}

		lpLinkService.SetOptions(options)
	}

	f.fillFaceProperties(responseParams, selectedFace)
	responseParams.Uri = nil
	responseParams.LocalUri = nil
	f.manager.sendCtrlResp(interest, 200, "OK", responseParams)
}

func (f *FaceModule) destroy(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(f, interest)
	if params == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.FaceId == nil {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing FaceId)", nil)
		return
	}

	if link := face.FaceTable.Get(*params.FaceId); link != nil {
		link.Close()
		core.LogInfo(f, "Destroyed face with FaceID=", *params.FaceId)
	} else {
		core.LogInfo(f, "Ignoring attempt to delete non-existent face with FaceID=", *params.FaceId)
	}

	f.manager.sendCtrlResp(interest, 200, "OK", params)
}

func (f *FaceModule) list(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	faces := make(map[uint64]face.LinkService)
	faceIDs := make([]uint64, 0)
	for _, face := range face.FaceTable.GetAll() {
		faces[face.FaceID()] = face
		faceIDs = append(faceIDs, face.FaceID())
	}
	// We have to sort these or they appear in a strange order
	sort.Slice(faceIDs, func(a int, b int) bool { return faceIDs[a] < faceIDs[b] })
	dataset := &mgmt.FaceStatusMsg{}
	for _, pos := range faceIDs {
		dataset.Vals = append(dataset.Vals, f.createDataset(faces[pos]))
	}

	name := LOCAL_PREFIX.Append(
		enc.NewStringComponent(enc.TypeGenericNameComponent, "faces"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "list"),
	)
	f.manager.sendStatusDataset(interest, name, dataset.Encode())
}

func (f *FaceModule) query(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		// Name not long enough to contain FaceQueryFilter
		core.LogWarn(f, "Missing FaceQueryFilter in ", interest.Name())
		return
	}
	filterV, err := mgmt.ParseFaceQueryFilter(enc.NewBufferReader(interest.Name()[len(LOCAL_PREFIX)+2].Val), true)
	if err != nil || filterV == nil || filterV.Val == nil {
		return
	}
	filter := filterV.Val

	// canonize URI if present in filter
	var filterUri *defn.URI
	if filter.Uri != nil {
		filterUri = defn.DecodeURIString(*filter.Uri)
		if filterUri == nil {
			core.LogWarn(f, "Cannot decode URI in FaceQueryFilter ", filterUri)
			return
		}
		err = filterUri.Canonize()
		if err != nil {
			core.LogWarn(f, "Cannot canonize URI in FaceQueryFilter ", filterUri)
			return
		}
	}

	// filter all faces to match filter
	faces := face.FaceTable.GetAll()
	matchingFaces := make([]int, 0)
	for pos, face := range faces {
		if filter.FaceId != nil && *filter.FaceId != face.FaceID() {
			continue
		}

		if filter.UriScheme != nil &&
			*filter.UriScheme != face.LocalURI().Scheme() &&
			*filter.UriScheme != face.RemoteURI().Scheme() {
			continue
		}

		if filterUri != nil && filterUri.String() != face.RemoteURI().String() {
			continue
		}

		if filter.LocalUri != nil && *filter.LocalUri != face.LocalURI().String() {
			continue
		}

		if filter.FaceScope != nil && *filter.FaceScope != uint64(face.Scope()) {
			continue
		}

		if filter.FacePersistency != nil && *filter.FacePersistency != uint64(face.Persistency()) {
			continue
		}

		if filter.LinkType != nil && *filter.LinkType != uint64(face.LinkType()) {
			continue
		}

		matchingFaces = append(matchingFaces, pos)
	}

	// We have to sort these or they appear in a strange order
	sort.Slice(matchingFaces, func(a int, b int) bool { return matchingFaces[a] < matchingFaces[b] })

	dataset := &mgmt.FaceStatusMsg{}
	for _, pos := range matchingFaces {
		dataset.Vals = append(dataset.Vals, f.createDataset(faces[pos]))
	}

	f.manager.sendStatusDataset(interest, interest.Name(), dataset.Encode())
}

func (f *FaceModule) createDataset(selectedFace face.LinkService) *mgmt.FaceStatus {
	faceDataset := &mgmt.FaceStatus{
		FaceId:          selectedFace.FaceID(),
		Uri:             selectedFace.RemoteURI().String(),
		LocalUri:        selectedFace.LocalURI().String(),
		FaceScope:       uint64(selectedFace.Scope()),
		FacePersistency: uint64(selectedFace.Persistency()),
		LinkType:        uint64(selectedFace.LinkType()),
		Mtu:             utils.IdPtr(uint64(selectedFace.MTU())),
		NInInterests:    selectedFace.NInInterests(),
		NInData:         selectedFace.NInData(),
		NInNacks:        0,
		NOutInterests:   selectedFace.NOutInterests(),
		NOutData:        selectedFace.NOutData(),
		NOutNacks:       0,
		NInBytes:        selectedFace.NInBytes(),
		NOutBytes:       selectedFace.NInBytes(),
	}
	if selectedFace.ExpirationPeriod() != 0 {
		faceDataset.ExpirationPeriod = utils.IdPtr(uint64(selectedFace.ExpirationPeriod().Milliseconds()))
	}
	linkService, ok := selectedFace.(*face.NDNLPLinkService)
	if ok {
		options := linkService.Options()

		faceDataset.BaseCongestionMarkInterval = utils.IdPtr(uint64(options.BaseCongestionMarkingInterval.Nanoseconds()))
		faceDataset.DefaultCongestionThreshold = utils.IdPtr(options.DefaultCongestionThresholdBytes)
		faceDataset.Flags = options.Flags()
		if options.IsConsumerControlledForwardingEnabled {
			// This one will only be enabled if the other two local fields are enabled (and vice versa)
			faceDataset.Flags |= face.FaceFlagLocalFields
		}
		if options.IsCongestionMarkingEnabled {
			faceDataset.Flags |= face.FaceFlagCongestionMarking
		}
	}

	return faceDataset
}

func (f *FaceModule) fillFaceProperties(params *mgmt.ControlArgs, selectedFace face.LinkService) {
	params.FaceId = utils.IdPtr(selectedFace.FaceID())
	params.Uri = utils.IdPtr(selectedFace.RemoteURI().String())
	params.LocalUri = utils.IdPtr(selectedFace.LocalURI().String())
	params.FacePersistency = utils.IdPtr(uint64(selectedFace.Persistency()))
	params.Mtu = utils.IdPtr(uint64(selectedFace.MTU()))
	params.Flags = utils.IdPtr(uint64(0))

	if linkService, ok := selectedFace.(*face.NDNLPLinkService); ok {
		options := linkService.Options()
		params.BaseCongestionMarkInterval = utils.IdPtr(uint64(options.BaseCongestionMarkingInterval.Nanoseconds()))
		params.DefaultCongestionThreshold = utils.IdPtr(options.DefaultCongestionThresholdBytes)
		params.Flags = utils.IdPtr(uint64(options.Flags()))
	}
}
