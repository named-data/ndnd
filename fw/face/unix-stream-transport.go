/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"fmt"
	"net"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/face/impl"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// UnixStreamTransport is a Unix stream transport for communicating with local applications.
type UnixStreamTransport struct {
	conn *net.UnixConn
	transportBase
}

// MakeUnixStreamTransport creates a Unix stream transport.
func MakeUnixStreamTransport(remoteURI *defn.URI, localURI *defn.URI, conn net.Conn) (*UnixStreamTransport, error) {
	// Validate URIs
	if !remoteURI.IsCanonical() || remoteURI.Scheme() != "fd" || !localURI.IsCanonical() || localURI.Scheme() != "unix" {
		return nil, core.ErrNotCanonical
	}

	t := new(UnixStreamTransport)
	t.makeTransportBase(remoteURI, localURI, spec_mgmt.PersistencyPersistent, defn.Local, defn.PointToPoint, defn.MaxNDNPacketSize)

	// Set connection
	t.conn = conn.(*net.UnixConn)
	t.running.Store(true)

	return t, nil
}

func (t *UnixStreamTransport) String() string {
	return fmt.Sprintf("UnixStreamTransport, FaceID=%d, RemoteURI=%s, LocalURI=%s", t.faceID, t.remoteURI, t.localURI)
}

// SetPersistency changes the persistency of the face.
func (t *UnixStreamTransport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	if persistency == t.persistency {
		return true
	}

	if persistency == spec_mgmt.PersistencyPersistent {
		t.persistency = persistency
		return true
	}

	return false
}

// GetSendQueueSize returns the current size of the send queue.
func (t *UnixStreamTransport) GetSendQueueSize() uint64 {
	rawConn, err := t.conn.SyscallConn()
	if err != nil {
		core.LogWarn(t, "Unable to get raw connection to get socket length: ", err)
	}
	return impl.SyscallGetSocketSendQueueSize(rawConn)
}

func (t *UnixStreamTransport) sendFrame(frame []byte) {
	if !t.running.Load() {
		return
	}

	if len(frame) > t.MTU() {
		core.LogWarn(t, "Attempted to send frame larger than MTU - DROP")
		return
	}

	_, err := t.conn.Write(frame)
	if err != nil {
		core.LogWarn(t, "Unable to send on socket - DROP and Face DOWN")
		t.Close()
		return
	}

	t.nOutBytes += uint64(len(frame))
}

func (t *UnixStreamTransport) runReceive() {
	defer t.Close()

	err := readTlvStream(t.conn, func(b []byte) {
		t.nInBytes += uint64(len(b))
		t.linkService.handleIncomingFrame(b)
	}, nil)
	if err != nil && t.running.Load() {
		core.LogWarn(t, "Unable to read from socket (", err, ") - Face DOWN")
	}
}

func (t *UnixStreamTransport) Close() {
	if t.running.Swap(false) {
		t.conn.Close()
	}
}
