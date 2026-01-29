/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/fw"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// LinkService is an interface for link service implementations
type LinkService interface {
	String() string
	Transport() transport
	SetFaceID(faceID uint64)

	FaceID() uint64
	LocalURI() *defn.URI
	RemoteURI() *defn.URI
	Persistency() spec_mgmt.Persistency
	SetPersistency(persistency spec_mgmt.Persistency)
	Scope() defn.Scope
	LinkType() defn.LinkType
	MTU() int
	SetMTU(mtu int)

	ExpirationPeriod() time.Duration
	State() defn.State

	// Run is the main entry point for running face thread
	// initial is optional new incoming frame
	Run(initial []byte)

	// Add a packet to the send queue for this link service
	SendPacket(out dispatch.OutPkt)
	// Synchronously handle an incoming frame and dispatch to fw
	handleIncomingFrame(frame []byte)

	// Close the face
	Close()

	// Counters
	NInInterests() uint64
	NInData() uint64
	NInBytes() uint64
	NOutInterests() uint64
	NOutData() uint64
	NOutBytes() uint64
}

// linkServiceBase is the type upon which all link service implementations should be built
type linkServiceBase struct {
	faceID    uint64
	transport transport
	stopped   chan bool
	sendQueue chan dispatch.OutPkt

	// Counters
	nInInterests  uint64
	nInData       uint64
	nOutInterests uint64
	nOutData      uint64
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable string that describes the link service, displaying its transport type if present, otherwise its face ID.
func (l *linkServiceBase) String() string {
	if l.transport != nil {
		return fmt.Sprintf("link-service (%s)", l.transport)
	}

	return fmt.Sprintf("link-service (faceid=%d)", l.faceID)
}

// (AI GENERATED DESCRIPTION): Sets the link service’s face ID and propagates the change to its underlying transport if one exists.
func (l *linkServiceBase) SetFaceID(faceID uint64) {
	l.faceID = faceID
	if l.transport != nil {
		l.transport.setFaceID(faceID)
	}
}

//
// "Constructors" and threading
//

// (AI GENERATED DESCRIPTION): Initializes the link service base by creating a `stopped` signal channel and a buffered `sendQueue` channel sized according to the face queue configuration.
func (l *linkServiceBase) makeLinkServiceBase() {
	l.stopped = make(chan bool)
	l.sendQueue = make(chan dispatch.OutPkt, CfgFaceQueueSize())
}

//
// Getters
//

// Transport returns the transport for the face.
func (l *linkServiceBase) Transport() transport {
	return l.transport
}

// FaceID returns the ID of the face
func (l *linkServiceBase) FaceID() uint64 {
	return l.faceID
}

// LocalURI returns the local URI of the underlying transport
func (l *linkServiceBase) LocalURI() *defn.URI {
	return l.transport.LocalURI()
}

// RemoteURI returns the remote URI of the underlying transport
func (l *linkServiceBase) RemoteURI() *defn.URI {
	return l.transport.RemoteURI()
}

// Persistency returns the MTU of the underlying transport.
func (l *linkServiceBase) Persistency() spec_mgmt.Persistency {
	return l.transport.Persistency()
}

// SetPersistency sets the MTU of the underlying transport.
func (l *linkServiceBase) SetPersistency(persistency spec_mgmt.Persistency) {
	l.transport.SetPersistency(persistency)
}

// Scope returns the scope of the underlying transport.
func (l *linkServiceBase) Scope() defn.Scope {
	return l.transport.Scope()
}

// LinkType returns the type of the link.
func (l *linkServiceBase) LinkType() defn.LinkType {
	return l.transport.LinkType()
}

// MTU returns the MTU of the underlying transport.
func (l *linkServiceBase) MTU() int {
	return l.transport.MTU()
}

// SetMTU sets the MTU of the underlying transport.
func (l *linkServiceBase) SetMTU(mtu int) {
	l.transport.SetMTU(mtu)
}

// ExpirationPeriod returns the time until the underlying transport expires. If transport not on-demand, returns 0.
func (l *linkServiceBase) ExpirationPeriod() time.Duration {
	return l.transport.ExpirationPeriod()
}

// State returns the state of the underlying transport.
func (l *linkServiceBase) State() defn.State {
	if l.transport.IsRunning() {
		return defn.Up
	}
	return defn.Down
}

//
// Counters
//

// NInInterests returns the number of Interests received on this face.
func (l *linkServiceBase) NInInterests() uint64 {
	return l.nInInterests
}

// NInData returns the number of Data packets received on this face.
func (l *linkServiceBase) NInData() uint64 {
	return l.nInData
}

// NInBytes returns the number of link-layer bytes received on this face.
func (l *linkServiceBase) NInBytes() uint64 {
	return l.transport.NInBytes()
}

// NOutInterests returns the number of Interests sent on this face.
func (l *linkServiceBase) NOutInterests() uint64 {
	return l.nOutInterests
}

// NInData returns the number of Data packets sent on this face.
func (l *linkServiceBase) NOutData() uint64 {
	return l.nOutData
}

// NOutBytes returns the number of link-layer bytes sent on this face.
func (l *linkServiceBase) NOutBytes() uint64 {
	return l.transport.NOutBytes()
}

// Close the underlying transport
func (l *linkServiceBase) Close() {
	l.transport.Close()
}

//
// Forwarding pipeline
//

// SendPacket adds a packet to the send queue for this link service
func (l *linkServiceBase) SendPacket(out dispatch.OutPkt) {
	select {
	case l.sendQueue <- out:
		// Packet queued successfully
		core.Log.Trace(l, "Queued packet for link service")
	default:
		// Drop packet due to congestion
		core.Log.Debug(l, "Dropped packet due to congestion")

		// TODO: Signal congestion
	}
}

// (AI GENERATED DESCRIPTION): Routes an Interest packet to the correct forwarding thread by hashing its name and enqueuing it for processing.
func (l *linkServiceBase) dispatchInterest(pkt *defn.Pkt) {
	if pkt.L3.Interest == nil {
		panic("dispatchInterest called with packet that is not Interest")
	}

	// Store name for easy access
	pkt.Name = pkt.L3.Interest.NameV

	// Hash name to thread
	thread := fw.HashNameToFwThread(pkt.Name)
	core.Log.Trace(l, "Dispatched Interest", "thread", thread)
	dispatch.GetFWThread(thread).QueueInterest(pkt)
}

// (AI GENERATED DESCRIPTION): Routes an incoming Data packet to the appropriate forwarding thread(s) by examining its PIT token or name prefix, handling local producer packets that lack tokens, and logging the dispatch.
func (l *linkServiceBase) dispatchData(pkt *defn.Pkt) {
	if pkt.L3.Data == nil {
		panic("dispatchData called with packet that is not Data")
	}

	// Store name for easy access
	pkt.Name = pkt.L3.Data.NameV

	// Decode PitToken. If it's for us, it's a uint16 + uint32.
	if len(pkt.PitToken) == 6 {
		thread := binary.BigEndian.Uint16(pkt.PitToken)
		fwThread := dispatch.GetFWThread(int(thread))
		if fwThread == nil {
			core.Log.Error(l, "Invalid PIT token attached to Data packet")
			return
		}

		core.Log.Trace(l, "Dispatched Data", "thread", thread)
		fwThread.QueueData(pkt)
		return
	}

	// Only if from a local face (and therefore from a producer), dispatch to
	// threads matching every prefix. We need to do this because producers do
	// not attach PIT tokens to their data packets.
	if l.Scope() == defn.Local {
		for i, match := range fw.HashNameToAllPrefixFwThreads(pkt.Name) {
			if match {
				core.Log.Trace(l, "Prefix dispatched local-origin Data", "thread", i)
				dispatch.GetFWThread(i).QueueData(pkt)
			}
		}
		return
	}

	// Only exact-match for now (no CanBePrefix)
	thread := fw.HashNameToFwThread(pkt.Name)
	core.Log.Trace(l, "Dispatched Data", "thread", thread)
	dispatch.GetFWThread(thread).QueueData(pkt)
}
