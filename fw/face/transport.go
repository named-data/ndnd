/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"sync/atomic"
	"time"

	defn "github.com/named-data/ndnd/fw/defn"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// transport provides an interface for transports for specific face types
type transport interface {
	String() string
	setFaceID(faceID uint64)
	setLinkService(linkService LinkService)

	RemoteURI() *defn.URI
	LocalURI() *defn.URI
	Persistency() spec_mgmt.Persistency
	SetPersistency(persistency spec_mgmt.Persistency) bool
	Scope() defn.Scope
	LinkType() defn.LinkType
	MTU() int
	SetMTU(mtu int)
	ExpirationPeriod() time.Duration
	FaceID() uint64

	// Get the number of queued outgoing packets
	GetSendQueueSize() uint64
	// Send a frame (make if copy if necessary)
	sendFrame([]byte)
	// Receive frames in an infinite loop
	runReceive()
	// Transport is currently running (up)
	IsRunning() bool
	// Close the transport (runReceive should exit)
	Close()

	// Counters
	NInBytes() uint64
	NOutBytes() uint64
}

// transportBase provides logic common types between transport types
type transportBase struct {
	linkService LinkService
	running     atomic.Bool

	faceID         uint64
	remoteURI      *defn.URI
	localURI       *defn.URI
	scope          defn.Scope
	persistency    spec_mgmt.Persistency
	linkType       defn.LinkType
	mtu            int
	expirationTime *time.Time

	// Counters
	nInBytes  uint64
	nOutBytes uint64
}

// (AI GENERATED DESCRIPTION): Initializes a transportBase instance with the specified remote and local URIs, persistency, scope, link type, and MTU values, resetting its running flag to false.
func (t *transportBase) makeTransportBase(
	remoteURI *defn.URI,
	localURI *defn.URI,
	persistency spec_mgmt.Persistency,
	scope defn.Scope,
	linkType defn.LinkType,
	mtu int,
) {
	t.running = atomic.Bool{}
	t.remoteURI = remoteURI
	t.localURI = localURI
	t.persistency = persistency
	t.scope = scope
	t.linkType = linkType
	t.mtu = mtu
}

//
// Setters
//

// (AI GENERATED DESCRIPTION): Assigns the given face ID to the transport base.
func (t *transportBase) setFaceID(faceID uint64) {
	t.faceID = faceID
}

// (AI GENERATED DESCRIPTION): Sets the transport’s LinkService to the given LinkService.
func (t *transportBase) setLinkService(linkService LinkService) {
	t.linkService = linkService
}

//
// Getters
//

// (AI GENERATED DESCRIPTION): Returns the local URI of the transport instance.
func (t *transportBase) LocalURI() *defn.URI {
	return t.localURI
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the remote URI associated with this transport instance.
func (t *transportBase) RemoteURI() *defn.URI {
	return t.remoteURI
}

// (AI GENERATED DESCRIPTION): Returns the persistency mode associated with the transport base instance.
func (t *transportBase) Persistency() spec_mgmt.Persistency {
	return t.persistency
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the transport’s scope value.
func (t *transportBase) Scope() defn.Scope {
	return t.scope
}

// (AI GENERATED DESCRIPTION): Returns the link type associated with this transport.
func (t *transportBase) LinkType() defn.LinkType {
	return t.linkType
}

// (AI GENERATED DESCRIPTION): Returns the maximum transmission unit (MTU) size configured for the transport instance.
func (t *transportBase) MTU() int {
	return t.mtu
}

// (AI GENERATED DESCRIPTION): Sets the transport’s maximum transmission unit (MTU) to the specified integer value.
func (t *transportBase) SetMTU(mtu int) {
	t.mtu = mtu
}

// ExpirationPeriod returns the time until this face expires.
// If transport not on-demand, returns 0.
func (t *transportBase) ExpirationPeriod() time.Duration {
	if t.expirationTime == nil || t.persistency != spec_mgmt.PersistencyOnDemand {
		return 0
	}
	return time.Until(*t.expirationTime)
}

// (AI GENERATED DESCRIPTION): Returns the unique face ID associated with this transport instance.
func (t *transportBase) FaceID() uint64 {
	return t.faceID
}

// (AI GENERATED DESCRIPTION): Returns `true` if the transport instance is currently running, otherwise `false`.
func (t *transportBase) IsRunning() bool {
	return t.running.Load()
}

//
// Counters
//

// (AI GENERATED DESCRIPTION): Returns the total number of bytes received by the transport instance.
func (t *transportBase) NInBytes() uint64 {
	return t.nInBytes
}

// (AI GENERATED DESCRIPTION): Returns the total number of bytes that have been sent through this transport.
func (t *transportBase) NOutBytes() uint64 {
	return t.nOutBytes
}
