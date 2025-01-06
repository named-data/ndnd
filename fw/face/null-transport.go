/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"strconv"

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

func (t *NullTransport) String() string {
	return "NullTransport, FaceID=" + strconv.FormatUint(t.faceID, 10) + ", RemoteURI=" + t.remoteURI.String() + ", LocalURI=" + t.localURI.String()
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

func (t *NullTransport) sendFrame([]byte) {
	// Do nothing
}

func (t *NullTransport) runReceive() {
	t.running.Store(true)
	<-t.close
}

func (t *NullTransport) Close() {
	if t.running.Swap(false) {
		t.close <- true
	}
}
