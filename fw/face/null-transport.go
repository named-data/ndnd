/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"fmt"

	defn "github.com/named-data/ndnd/fw/defn"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// NullTransport is a transport that drops all packets.
type NullTransport struct {
	transportBase
	close chan bool
}

// MakeNullTransport makes a NullTransport.
func MakeNullTransport() *NullTransport {
	t := &NullTransport{
		close: make(chan bool),
	}
	t.makeTransportBase(
		defn.MakeNullFaceURI(),
		defn.MakeNullFaceURI(),
		spec_mgmt.PersistencyPermanent,
		defn.NonLocal,
		defn.PointToPoint,
		defn.MaxNDNPacketSize)
	return t
}

// (AI GENERATED DESCRIPTION): Returns a formatted string describing the NullTransport, including its face ID, remote URI, and local URI.
func (t *NullTransport) String() string {
	return fmt.Sprintf("null-transport (faceid=%d remote=%s local=%s)", t.faceID, t.remoteURI, t.localURI)
}

// SetPersistency changes the persistency of the face.
func (t *NullTransport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	if persistency == t.persistency {
		return true
	}

	if persistency == spec_mgmt.PersistencyPermanent {
		t.persistency = persistency
		return true
	}

	return false
}

// GetSendQueueSize returns the current size of the send queue.
func (t *NullTransport) GetSendQueueSize() uint64 {
	return 0
}

// (AI GENERATED DESCRIPTION): Discards the supplied frame data without transmitting it, serving as the no‑op implementation for NullTransport.
func (t *NullTransport) sendFrame([]byte) {
	// Do nothing
}

// (AI GENERATED DESCRIPTION): Marks the NullTransport as running and blocks until a signal is received on the close channel to terminate the receiver.
func (t *NullTransport) runReceive() {
	t.running.Store(true)
	<-t.close
}

// (AI GENERATED DESCRIPTION): Atomically marks the transport as inactive and, if it was previously running, sends a signal on the close channel to trigger shutdown.
func (t *NullTransport) Close() {
	if t.running.Swap(false) {
		t.close <- true
	}
}
