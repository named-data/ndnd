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
	"github.com/named-data/ndnd/fw/face"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
)

// Thread Represents the management thread
type Thread struct {
	face           face.LinkService
	transport      *face.InternalTransport
	localPrefix    enc.Name
	nonLocalPrefix enc.Name
	modules        map[string]Module
	timer          ndn.Timer
}

// MakeMgmtThread creates a new management thread.
func MakeMgmtThread() *Thread {
	m := new(Thread)
	m.timer = basic_engine.NewTimer()

	var err error
	m.localPrefix, err = enc.NameFromStr("/localhost/nfd")
	if err != nil {
		core.LogFatal(m, "Unable to create name for management prefix: ", err)
	}
	m.nonLocalPrefix, err = enc.NameFromStr("/localhop/nfd")
	if err != nil {
		core.LogFatal(m, "Unable to create name for management prefix: ", err)
	}

	m.modules = make(map[string]Module)
	m.registerModule("cs", new(ContentStoreModule))
	m.registerModule("faces", new(FaceModule))
	m.registerModule("fib", new(FIBModule))
	m.registerModule("rib", new(RIBModule))
	m.registerModule("status", new(ForwarderStatusModule))
	m.registerModule("strategy-choice", new(StrategyChoiceModule))

	// readvertisers run in the management thread for ease of
	// implementation, since they use the internal transport
	if core.GetConfig().Tables.Rib.ReadvertiseNlsr {
		table.AddReadvertiser(NewNlsrReadvertiser(m))
	}

	return m
}

func (m *Thread) String() string {
	return "Management"
}

func (m *Thread) registerModule(name string, module Module) {
	m.modules[name] = module
	module.registerManager(m)
}

func (m *Thread) prefixLength() int {
	return len(m.localPrefix)
}

func (m *Thread) sendInterest(name enc.Name, params enc.Wire) {
	config := ndn.InterestConfig{
		MustBeFresh: true,
		Nonce:       utils.IdPtr(rand.Uint64()),
	}
	interest, err := spec.Spec{}.MakeInterest(
		name, &config, params, sec.NewSha256IntSigner(m.timer))
	if err != nil {
		core.LogWarn(m, "Unable to encode Interest for ", name, ": ", err)
		return
	}

	m.transport.Send(interest.Wire, nil, nil)
	core.LogTrace(m, "Sent management Interest for ", interest.FinalName)
}

func (m *Thread) sendResponse(response *mgmt.ControlResponse, interest ndn.Interest, pitToken []byte, inFace uint64) {
	encodedResponse := response.Encode()
	data, err := spec.Spec{}.MakeData(interest.Name(),
		&ndn.DataConfig{
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
			Freshness:   utils.IdPtr(time.Second),
		},
		encodedResponse,
		sec.NewSha256Signer(),
	)
	if err != nil {
		core.LogWarn(m, "Unable to encode ControlResponse Data for ", interest.Name(), ": ", err)
		return
	}

	m.transport.Send(data.Wire, pitToken, &inFace)
	core.LogTrace(m, "Sent ControlResponse for ", interest.Name())
}

// Run management thread
func (m *Thread) Run() {
	core.LogInfo(m, "Starting management")

	// Create and register Internal transport
	m.face, m.transport = face.RegisterInternalTransport()
	faces, err := enc.NameFromStr("/localhost/nfd")
	if err != nil {
		core.LogFatal(m, "Unable to create name for management prefix: ", err)
	}
	table.FibStrategyTable.InsertNextHopEnc(faces, m.face.FaceID(), 0)
	if enableLocalhopManagement {
		add1, _ := enc.NameFromStr("/localhop/nfd")
		table.FibStrategyTable.InsertNextHopEnc(add1, m.face.FaceID(), 0)
	}
	for {
		fragment, pitToken, inFace := m.transport.Receive()
		if fragment == nil {
			// Indicates that internal face has quit, which means it's time for us to quit
			core.LogInfo(m, "Face quit, so management quitting")
			break
		}
		core.LogTrace(m, "Received block on face, IncomingFaceID=", inFace)

		pkt, _, err := spec.ReadPacket(enc.NewWireReader(fragment))
		if err != nil {
			// Indicates that internal face has quit, which means it's time for us to quit
			core.LogInfo(m, "Unable to decode internal packet, drop")
			continue
		}

		// We only expect Interests, so drop Data packets
		if pkt.Interest == nil {
			core.LogDebug(m, "Dropping received non-Interest packet")
			continue
		}
		interest := pkt.Interest

		// Ensure Interest name matches expectations
		if len(interest.NameV) < len(m.localPrefix)+2 { // Module + Verb
			core.LogInfo(m, "Control command name ", interest.Name().String(), " has unexpected number of components - DROP")
			continue
		}
		if !m.localPrefix.IsPrefix(interest.NameV) && !m.nonLocalPrefix.IsPrefix(interest.Name()) {
			core.LogInfo(m, "Control command name ", interest.Name(), " has unexpected prefix - DROP")
			continue
		}

		core.LogTrace(m, "Received management Interest ", interest.Name())

		// Dispatch interest based on name
		moduleName := interest.NameV[len(m.localPrefix)].String()
		if module, ok := m.modules[moduleName]; ok {
			module.handleIncomingInterest(interest, pitToken, inFace)
		} else {
			core.LogWarn(m, "Received management Interest for unknown module ", moduleName)
			response := makeControlResponse(501, "Unknown module", nil)
			if response == nil {
				core.LogError(m, "Unable to encode control response")
				continue
			}
			m.sendResponse(response, interest, pitToken, inFace)
		}
	}
}
