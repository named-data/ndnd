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
	"github.com/named-data/ndnd/std/types/optional"
)

// FaceModule is the module that handles Face Management.
type FaceModule struct {
	manager *Thread
}

// (AI GENERATED DESCRIPTION): Returns the fixed identifier string for the Face module (`"mgmt-face"`), used for naming and logging.
func (f *FaceModule) String() string {
	return "mgmt-face"
}

// (AI GENERATED DESCRIPTION): Assigns the supplied `Thread` instance as the manager for the `FaceModule`, storing it in the module’s `manager` field.
func (f *FaceModule) registerManager(manager *Thread) {
	f.manager = manager
}

// (AI GENERATED DESCRIPTION): Returns the manager Thread associated with this FaceModule.
func (f *FaceModule) getManager() *Thread {
	return f.manager
}

// (AI GENERATED DESCRIPTION): Handles a local face‑management Interest by routing it to the appropriate create, update, destroy, list, or query handler, or returning a 501 error for unknown verbs.
func (f *FaceModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.Log.Warn(f, "Received face management Interest from non-local source - DROP")
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
		core.Log.Warn(f, "Received Interest for non-existent verb", "verb", verb)
		f.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

// (AI GENERATED DESCRIPTION): Creates a new unicast UDP or TCP face from the supplied ControlParameters, performing validation, configuring the transport and NDNLP link service, and replying with the face properties or an error status.
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

	if !params.Uri.IsSet() {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	URI := defn.DecodeURIString(params.Uri.Unwrap())
	if URI == nil || URI.Canonize() != nil {
		f.manager.sendCtrlResp(interest, 400, "URI could not be canonized", nil)
		return
	}

	if (params.Flags.IsSet() && !params.Mask.IsSet()) || (!params.Flags.IsSet() && params.Mask.IsSet()) {
		f.manager.sendCtrlResp(interest, 409, "Incomplete Flags/Mask combination", nil)
		return
	}

	// Ensure does not conflict with existing face
	existingFace := face.FaceTable.GetByURI(URI)
	if existingFace != nil {
		core.Log.Warn(f, "Cannot create face, conflicts with existing face",
			"faceid", existingFace.FaceID(), "uri", existingFace.RemoteURI())
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
		if pers, ok := params.FacePersistency.Get(); ok && (pers == uint64(mgmt.PersistencyPersistent) || pers == uint64(mgmt.PersistencyPermanent)) {
			persistency = mgmt.Persistency(pers)
		} else if params.FacePersistency.IsSet() {
			f.manager.sendCtrlResp(interest, 406, "Unacceptable persistency", nil)
			return
		}

		// Check congestion control
		baseCongestionMarkingInterval := 100 * time.Millisecond
		if bcmi, ok := params.BaseCongestionMarkInterval.Get(); ok {
			baseCongestionMarkingInterval = time.Duration(bcmi) * time.Nanosecond
		}

		defaultCongestionThresholdBytes := uint64(math.Pow(2, 16))
		if dct, ok := params.DefaultCongestionThreshold.Get(); ok {
			defaultCongestionThresholdBytes = dct
		}

		// Create new UDP face
		transport, err := face.MakeUnicastUDPTransport(URI, nil, persistency)
		if err != nil {
			core.Log.Warn(f, "Unable to create unicast UDP face", "uri", URI, "err", err)
			f.manager.sendCtrlResp(interest, 406, "Transport error", nil)
			return
		}

		if mtu, ok := params.Mtu.Get(); ok {
			transport.SetMTU(min(int(mtu), defn.MaxNDNPacketSize))
		}

		// NDNLP link service parameters
		options := face.MakeNDNLPLinkServiceOptions()
		if params.Flags.IsSet() && params.Mask.IsSet() {
			// Mask already guaranteed to be present if Flags is above
			flags := params.Flags.Unwrap()
			mask := params.Mask.Unwrap()

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
		if pers, ok := params.FacePersistency.Get(); ok && (pers == uint64(mgmt.PersistencyPersistent) || pers == uint64(mgmt.PersistencyPermanent)) {
			persistency = mgmt.Persistency(pers)
		} else if params.FacePersistency.IsSet() {
			f.manager.sendCtrlResp(interest, 406, "Unacceptable persistency", nil)
			return
		}

		// Check congestion control
		baseCongestionMarkingInterval := 100 * time.Millisecond
		if bcmi, ok := params.BaseCongestionMarkInterval.Get(); ok {
			baseCongestionMarkingInterval = time.Duration(bcmi) * time.Nanosecond
		}

		defaultCongestionThresholdBytes := uint64(math.Pow(2, 16))
		if dct, ok := params.DefaultCongestionThreshold.Get(); ok {
			defaultCongestionThresholdBytes = dct
		}

		// Create new TCP face
		transport, err := face.MakeUnicastTCPTransport(URI, nil, persistency)
		if err != nil {
			core.Log.Warn(f, "Unable to create unicast TCP face", "uri", URI, "err", err)
			f.manager.sendCtrlResp(interest, 406, "Transport error", nil)
			return
		}

		if mtu, ok := params.Mtu.Get(); ok {
			transport.SetMTU(min(int(mtu), defn.MaxNDNPacketSize))
		}

		// NDNLP link service parameters
		options := face.MakeNDNLPLinkServiceOptions()
		options.IsFragmentationEnabled = false // reliable stream
		if params.Flags.IsSet() && params.Mask.IsSet() {
			// Mask already guaranteed to be present if Flags is above
			flags := params.Flags.Unwrap()
			mask := params.Mask.Unwrap()

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
		core.Log.Warn(f, "Transport error when creating face", "uri", URI)
		f.manager.sendCtrlResp(interest, 504, "Transport error when creating face", nil)
		return
	}

	responseParams := &mgmt.ControlArgs{}
	f.fillFaceProperties(responseParams, linkService)
	f.manager.sendCtrlResp(interest, 200, "OK", responseParams)

	core.Log.Info(f, "Created face", "uri", URI)
}

// (AI GENERATED DESCRIPTION): Updates a specified NDN face according to the ControlParameters carried in an incoming Interest, validating and applying changes such as persistency, MTU, congestion options, and flag settings, then responds with the updated face properties.
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

	faceID := interest.inFace.Unwrap()
	if fid, ok := params.FaceId.Get(); ok && fid != 0 {
		faceID = fid
	}

	// Validate parameters
	responseParams := &mgmt.ControlArgs{}
	areParamsValid := true

	selectedFace := face.FaceTable.Get(faceID)
	if selectedFace == nil {
		core.Log.Warn(f, "Cannot update specified (or implicit) face because it does not exist", "faceid", faceID)
		f.manager.sendCtrlResp(interest, 404, "Face does not exist", &mgmt.ControlArgs{FaceId: optional.Some(faceID)})
		return
	}

	// Can't update null (or internal) faces via management
	if selectedFace.RemoteURI().Scheme() == "null" || selectedFace.RemoteURI().Scheme() == "internal" {
		f.manager.sendCtrlResp(interest, 401, "Face cannot be updated via management", &mgmt.ControlArgs{FaceId: optional.Some(faceID)})
		return
	}

	if pers, ok := params.FacePersistency.Get(); ok {
		if selectedFace.RemoteURI().Scheme() == "ether" && pers != uint64(mgmt.PersistencyPermanent) {
			responseParams.FacePersistency = params.FacePersistency
			areParamsValid = false
		} else if (selectedFace.RemoteURI().Scheme() == "udp4" || selectedFace.RemoteURI().Scheme() == "udp6") &&
			pers != uint64(mgmt.PersistencyPersistent) && pers != uint64(mgmt.PersistencyPermanent) {
			responseParams.FacePersistency = params.FacePersistency
			areParamsValid = false
		} else if selectedFace.LocalURI().Scheme() == "unix" && pers != uint64(mgmt.PersistencyPersistent) {
			responseParams.FacePersistency = params.FacePersistency
			areParamsValid = false
		}
	}

	if (params.Flags.IsSet() && !params.Mask.IsSet()) || (!params.Flags.IsSet() && params.Mask.IsSet()) {
		if params.Flags.IsSet() {
			responseParams.Flags.Set(params.Flags.Unwrap())
		}
		if params.Mask.IsSet() {
			responseParams.Mask.Set(params.Mask.Unwrap())
		}
		areParamsValid = false
	}

	if !areParamsValid {
		f.manager.sendCtrlResp(interest, 409, "ControlParameters are incorrect", responseParams)
		return
	}

	// Actually perform face updates

	// Persistency
	if pers, ok := params.FacePersistency.Get(); ok {
		// Correctness of FacePersistency already validated
		selectedFace.SetPersistency(mgmt.Persistency(pers))
	}

	// Set NDNLP link service options
	if lpLinkService := selectedFace.(*face.NDNLPLinkService); lpLinkService != nil {
		options := lpLinkService.Options()

		// Congestion
		if bcmi, ok := params.BaseCongestionMarkInterval.Get(); ok && time.Duration(bcmi)*time.Nanosecond != options.BaseCongestionMarkingInterval {
			options.BaseCongestionMarkingInterval = time.Duration(bcmi) * time.Nanosecond
			core.Log.Info(f, "Set BaseCongestionMarkingInterval", "faceid", faceID, "value", options.BaseCongestionMarkingInterval)
		}

		if dct, ok := params.DefaultCongestionThreshold.Get(); ok && dct != options.DefaultCongestionThresholdBytes {
			options.DefaultCongestionThresholdBytes = dct
			core.Log.Info(f, "Set DefaultCongestionThreshold", "faceid", faceID, "value", options.DefaultCongestionThresholdBytes)
		}

		// MTU
		if mtu, ok := params.Mtu.Get(); ok {
			oldMTU := selectedFace.MTU()
			newMTU := min(int(mtu), defn.MaxNDNPacketSize)
			selectedFace.SetMTU(newMTU)
			core.Log.Info(f, "Set MTU", "faceid", faceID, "value", newMTU, "old", oldMTU)
		}

		// Flags
		if params.Flags.IsSet() && params.Mask.IsSet() {
			flags := params.Flags.Unwrap()
			mask := params.Mask.Unwrap()

			if mask&face.FaceFlagLocalFields > 0 {
				if flags&face.FaceFlagLocalFields > 0 {
					core.Log.Info(f, "Enable local fields", "faceid", faceID)
					options.IsConsumerControlledForwardingEnabled = true
					options.IsIncomingFaceIndicationEnabled = true
					options.IsLocalCachePolicyEnabled = true
				} else {
					core.Log.Info(f, "Disable local fields", "faceid", faceID)
					options.IsConsumerControlledForwardingEnabled = false
					options.IsIncomingFaceIndicationEnabled = false
					options.IsLocalCachePolicyEnabled = false
				}
			}

			if mask&face.FaceFlagCongestionMarking > 0 {
				options.IsCongestionMarkingEnabled = flags&face.FaceFlagCongestionMarking > 0
				if flags&face.FaceFlagCongestionMarking > 0 {
					core.Log.Info(f, "Enable congestion marking", "faceid", faceID)
				} else {
					core.Log.Info(f, "Disable congestion marking", "faceid", faceID)
				}
			}
		}

		lpLinkService.SetOptions(options)
	}

	f.fillFaceProperties(responseParams, selectedFace)
	responseParams.Uri.Unset()
	responseParams.LocalUri.Unset()
	f.manager.sendCtrlResp(interest, 200, "OK", responseParams)
}

// (AI GENERATED DESCRIPTION): Handles a destroy‑face control Interest by validating the parameters, closing the specified face if it exists, and returning an appropriate control response.
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

	if !params.FaceId.IsSet() {
		f.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing FaceId)", nil)
		return
	}

	if link := face.FaceTable.Get(params.FaceId.Unwrap()); link != nil {
		link.Close()
		core.Log.Info(f, "Destroyed face", "faceid", params.FaceId.Unwrap())
	} else {
		core.Log.Info(f, "Ignoring attempt to delete non-existent face", "faceid", params.FaceId.Unwrap())
	}

	f.manager.sendCtrlResp(interest, 200, "OK", params)
}

// (AI GENERATED DESCRIPTION): Responds to a `faces/list` Interest on the local prefix by collecting all registered faces, assembling them into a sorted `FaceStatusMsg` dataset, and sending that dataset back to the requester.
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

	name := LOCAL_PREFIX.
		Append(enc.NewGenericComponent("faces")).
		Append(enc.NewGenericComponent("list"))
	f.manager.sendStatusDataset(interest, name, dataset.Encode())
}

// (AI GENERATED DESCRIPTION): Responds to a FaceQuery interest by filtering the local FaceTable according to the supplied FaceQueryFilter and sending back a dataset of matching FaceStatusMsg entries.
func (f *FaceModule) query(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		// Name not long enough to contain FaceQueryFilter
		core.Log.Warn(f, "Missing FaceQueryFilter", "name", interest.Name())
		return
	}
	filterV, err := mgmt.ParseFaceQueryFilter(enc.NewBufferView(interest.Name()[len(LOCAL_PREFIX)+2].Val), true)
	if err != nil || filterV == nil || filterV.Val == nil {
		return
	}
	filter := filterV.Val

	// canonize URI if present in filter
	var filterUri *defn.URI
	if furi, ok := filter.Uri.Get(); ok {
		filterUri = defn.DecodeURIString(furi)
		if filterUri == nil {
			core.Log.Warn(f, "Cannot decode URI in FaceQueryFilter", "uri", filterUri)
			return
		}
		err = filterUri.Canonize()
		if err != nil {
			core.Log.Warn(f, "Cannot canonize URI in FaceQueryFilter", "uri", filterUri)
			return
		}
	}

	// filter all faces to match filter
	faces := face.FaceTable.GetAll()
	matchingFaces := make([]int, 0)
	for pos, face := range faces {
		if fid, ok := filter.FaceId.Get(); ok && fid != face.FaceID() {
			continue
		}

		if scheme, ok := filter.UriScheme.Get(); ok &&
			scheme != face.LocalURI().Scheme() &&
			scheme != face.RemoteURI().Scheme() {
			continue
		}

		if filterUri != nil && filterUri.String() != face.RemoteURI().String() {
			continue
		}

		if localUri, ok := filter.LocalUri.Get(); ok && localUri != face.LocalURI().String() {
			continue
		}

		if scope, ok := filter.FaceScope.Get(); ok && scope != uint64(face.Scope()) {
			continue
		}

		if pers, ok := filter.FacePersistency.Get(); ok && pers != uint64(face.Persistency()) {
			continue
		}

		if lt, ok := filter.LinkType.Get(); ok && lt != uint64(face.LinkType()) {
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

// (AI GENERATED DESCRIPTION): Creates a `mgmt.FaceStatus` dataset from a `face.LinkService`, populating its identifiers, statistics, and optional NDN‑LP configuration flags for use in management reporting.
func (f *FaceModule) createDataset(selectedFace face.LinkService) *mgmt.FaceStatus {
	faceDataset := &mgmt.FaceStatus{
		FaceId:          selectedFace.FaceID(),
		Uri:             selectedFace.RemoteURI().String(),
		LocalUri:        selectedFace.LocalURI().String(),
		FaceScope:       uint64(selectedFace.Scope()),
		FacePersistency: uint64(selectedFace.Persistency()),
		LinkType:        uint64(selectedFace.LinkType()),
		Mtu:             optional.Some(uint64(selectedFace.MTU())),
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
		faceDataset.ExpirationPeriod = optional.Some(uint64(selectedFace.ExpirationPeriod().Milliseconds()))
	}
	linkService, ok := selectedFace.(*face.NDNLPLinkService)
	if ok {
		options := linkService.Options()

		faceDataset.BaseCongestionMarkInterval = optional.Some(uint64(options.BaseCongestionMarkingInterval.Nanoseconds()))
		faceDataset.DefaultCongestionThreshold = optional.Some(options.DefaultCongestionThresholdBytes)
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

// (AI GENERATED DESCRIPTION): Populates a mgmt.ControlArgs struct with the properties of the selected face (ID, remote/local URIs, persistency, MTU) and, if it is an NDNLPLinkService, its congestion‑marking options.
func (f *FaceModule) fillFaceProperties(params *mgmt.ControlArgs, selectedFace face.LinkService) {
	params.FaceId = optional.Some(selectedFace.FaceID())
	params.Uri = optional.Some(selectedFace.RemoteURI().String())
	params.LocalUri = optional.Some(selectedFace.LocalURI().String())
	params.FacePersistency = optional.Some(uint64(selectedFace.Persistency()))
	params.Mtu = optional.Some(uint64(selectedFace.MTU()))
	params.Flags = optional.Some(uint64(0))

	if linkService, ok := selectedFace.(*face.NDNLPLinkService); ok {
		options := linkService.Options()
		params.BaseCongestionMarkInterval = optional.Some(uint64(options.BaseCongestionMarkingInterval.Nanoseconds()))
		params.DefaultCongestionThreshold = optional.Some(options.DefaultCongestionThresholdBytes)
		params.Flags = optional.Some(uint64(options.Flags()))
	}
}
