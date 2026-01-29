/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2022 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"math/rand"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/face"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

var LOCAL_PREFIX = defn.LOCAL_PREFIX
var NON_LOCAL_PREFIX = defn.NON_LOCAL_PREFIX

// Thread Represents the management thread
type Thread struct {
	face      face.LinkService
	transport *face.InternalTransport
	modules   map[string]Module
	timer     ndn.Timer

	store  ndn.Store
	objDir *storage.MemoryFifoDir
	signer ndn.Signer
}

// (AI GENERATED DESCRIPTION): Returns the constant string “mgmt”, identifying the Thread as a management thread.
func (m *Thread) String() string {
	return "mgmt"
}

// MakeMgmtThread creates a new management thread.
func MakeMgmtThread() *Thread {
	m := &Thread{
		modules: make(map[string]Module),
		timer:   basic_engine.NewTimer(),
		store:   storage.NewMemoryStore(),
		objDir:  storage.NewMemoryFifoDir(32),
		signer:  signer.NewSha256Signer(),
	}

	m.registerModule("cs", new(ContentStoreModule))
	m.registerModule("faces", new(FaceModule))
	m.registerModule("fib", new(FIBModule))
	m.registerModule("rib", new(RIBModule))
	m.registerModule("status", new(ForwarderStatusModule))
	m.registerModule("strategy-choice", new(StrategyChoiceModule))

	// readvertisers run in the management thread for ease of
	// implementation, since they use the internal transport
	if core.C.Tables.Rib.ReadvertiseNlsr {
		table.AddReadvertiser(NewNlsrReadvertiser(m))
	}

	return m
}

// (AI GENERATED DESCRIPTION): Registers a module under a given name in the thread and links it to the thread by calling the module’s `registerManager` method.
func (m *Thread) registerModule(name string, module Module) {
	m.modules[name] = module
	module.registerManager(m)
}

// Run management thread
func (m *Thread) Run() {
	core.Log.Info(m, "Starting management thread")

	// Create and register Internal transport
	m.face, m.transport = face.RegisterInternalTransport()
	table.FibStrategyTable.InsertNextHopEnc(LOCAL_PREFIX, m.face.FaceID(), 0)
	if core.C.Mgmt.AllowLocalhop {
		table.FibStrategyTable.InsertNextHopEnc(NON_LOCAL_PREFIX, m.face.FaceID(), 0)
	}

	for {
		lpPkt := m.transport.Receive()
		if lpPkt == nil {
			// Indicates that internal face has quit, which means it's time for us to quit
			core.Log.Info(m, "Face quit, so management quitting")
			break
		}

		if !lpPkt.IncomingFaceId.IsSet() || len(lpPkt.Fragment) == 0 {
			core.Log.Warn(m, "Received malformed packet on internal face - DROP")
			continue
		}

		pkt, _, err := spec.ReadPacket(enc.NewWireView(lpPkt.Fragment))
		if err != nil {
			core.Log.Warn(m, "Unable to decode internal packet - DROP", "err", err)
			continue
		}

		// We only expect Interests, so drop Data packets
		if pkt.Interest == nil {
			core.Log.Debug(m, "Dropping received non-Interest packet")
			continue
		}

		// Create internal Interest object for easier handling
		interest := &Interest{
			Interest: *pkt.Interest,
			pitToken: lpPkt.PitToken,
			inFace:   lpPkt.IncomingFaceId,
		}

		// Ensure Interest name matches expectations
		if len(interest.Name()) < len(LOCAL_PREFIX)+2 { // Module + Verb
			core.Log.Warn(m, "Control command name has unexpected number of components - DROP", "name", interest.Name())
			continue
		}
		if !LOCAL_PREFIX.IsPrefix(interest.Name()) && !NON_LOCAL_PREFIX.IsPrefix(interest.Name()) {
			core.Log.Warn(m, "Control command name has unexpected prefix - DROP", "name", interest.Name())
			continue
		}

		core.Log.Trace(m, "Received management Interest", "name", interest.Name())

		// Look for any matching data in object store.
		// We only use exact match here since RDR is unnecessary.
		segment, err := m.store.Get(interest.Name(), false)
		if err == nil && segment != nil {
			m.transport.Send(&spec.LpPacket{
				Fragment:      enc.Wire{segment},
				PitToken:      interest.pitToken,
				NextHopFaceId: interest.inFace,
			})
			continue
		}

		// Dispatch interest based on name
		moduleName := interest.Name()[len(LOCAL_PREFIX)].String()
		if module, ok := m.modules[moduleName]; ok {
			module.handleIncomingInterest(interest)
		} else {
			core.Log.Warn(m, "Received management Interest for unknown module", "module", moduleName)
			m.sendCtrlResp(interest, 501, "Unknown module", nil)
		}
	}
}

// Send an Interest to the internal transport
func (m *Thread) sendInterest(name enc.Name, params enc.Wire) {
	config := ndn.InterestConfig{
		MustBeFresh: true,
		Nonce:       optional.Some(rand.Uint32()),
	}
	interest, err := spec.Spec{}.MakeInterest(name, &config, params, m.signer)
	if err != nil {
		core.Log.Warn(m, "Unable to encode Interest", "name", name, "err", err)
		return
	}

	m.transport.Send(&spec.LpPacket{Fragment: interest.Wire})
	core.Log.Trace(m, "Sent management Interest", "name", interest.FinalName)
}

// Send a Data packet to the internal transport
func (m *Thread) sendData(interest *Interest, name enc.Name, content enc.Wire) {
	data, err := spec.Spec{}.MakeData(name,
		&ndn.DataConfig{
			ContentType: optional.Some(ndn.ContentTypeBlob),
			Freshness:   optional.Some(time.Duration(0)),
		},
		content,
		m.signer,
	)
	if err != nil {
		core.Log.Warn(m, "Unable to encode Data", "name", interest.Name(), "err", err)
		return
	}

	m.transport.Send(&spec.LpPacket{
		Fragment:      data.Wire,
		PitToken:      interest.pitToken,
		NextHopFaceId: interest.inFace,
	})
	core.Log.Trace(m, "Sent management Data", "name", name)
}

// Send a ControlResponse Data packet to the internal transport
func (m *Thread) sendCtrlResp(interest *Interest, statusCode uint64, statusText string, params *mgmt.ControlArgs) {
	if params == nil {
		params = &mgmt.ControlArgs{}
	}

	res := &mgmt.ControlResponse{
		Val: &mgmt.ControlResponseVal{
			StatusCode: statusCode,
			StatusText: statusText,
			Params:     params,
		},
	}

	m.sendData(interest, interest.Name(), res.Encode())
}

// Create a segmented status dataset and send the first segment to the internal transport
func (m *Thread) sendStatusDataset(interest *Interest, name enc.Name, dataset enc.Wire) {
	objName, err := object.Produce(ndn.ProduceArgs{
		Name:            name.WithVersion(enc.VersionUnixMicro),
		Content:         dataset,
		FreshnessPeriod: time.Millisecond,
		NoMetadata:      true,
	}, m.store, m.signer)
	if err != nil {
		core.Log.Warn(m, "Unable to produce status dataset", "err", err)
		return
	}
	m.objDir.Push(objName)

	// Evict oldest object if we have too many
	if old := m.objDir.Pop(); old != nil {
		if err := m.store.RemovePrefix(old); err != nil {
			core.Log.Warn(m, "Unable to clean up old status dataset", "err", err)
		}
	}

	// Get first segment from object name
	segment, err := m.store.Get(objName.Append(enc.NewSegmentComponent(0)), false)
	if err != nil || segment == nil {
		core.Log.Warn(m, "Unable to get first segment of status dataset", "err", err)
		return
	}

	m.transport.Send(&spec.LpPacket{
		Fragment:      enc.Wire{segment},
		PitToken:      interest.pitToken,
		NextHopFaceId: interest.inFace,
	})
}
