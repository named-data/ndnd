/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/face/impl"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// UnicastUDPTransport is a unicast UDP transport.
type UnicastUDPTransport struct {
	dialer     *net.Dialer
	conn       *net.UDPConn
	localAddr  net.UDPAddr
	remoteAddr net.UDPAddr
	transportBase
}

// MakeUnicastUDPTransport creates a new unicast UDP transport.
func MakeUnicastUDPTransport(
	remoteURI *defn.URI,
	localURI *defn.URI,
	persistency spec_mgmt.Persistency,
) (*UnicastUDPTransport, error) {
	// Validate remote URI
	if remoteURI == nil || !remoteURI.IsCanonical() || (remoteURI.Scheme() != "udp4" && remoteURI.Scheme() != "udp6") {
		return nil, core.ErrNotCanonical
	}

	// Validate local URI
	if localURI != nil && (!localURI.IsCanonical() || remoteURI.Scheme() != localURI.Scheme()) {
		return nil, core.ErrNotCanonical
	}

	// Construct transport
	t := new(UnicastUDPTransport)
	t.makeTransportBase(remoteURI, localURI, persistency, defn.NonLocal, defn.PointToPoint, defn.MaxNDNPacketSize)
	t.expirationTime = new(time.Time)
	*t.expirationTime = time.Now().Add(udpLifetime)

	// Set scope
	ip := net.ParseIP(remoteURI.Path())
	if ip.IsLoopback() {
		t.scope = defn.Local
	} else {
		t.scope = defn.NonLocal
	}

	// Set local and remote addresses
	if localURI != nil {
		t.localAddr.IP = net.ParseIP(localURI.Path())
		t.localAddr.Port = int(localURI.Port())
	} else {
		t.localAddr.Port = int(UDPUnicastPort)
	}
	t.remoteAddr.IP = net.ParseIP(remoteURI.Path())
	t.remoteAddr.Port = int(remoteURI.Port())

	// Configure dialer so we can allow address reuse
	// Unlike TCP, we don't need to do this in a separate goroutine because
	// we don't need to wait for the connection to be established
	t.dialer = &net.Dialer{LocalAddr: &t.localAddr, Control: impl.SyscallReuseAddr}
	remote := net.JoinHostPort(t.remoteURI.Path(), strconv.Itoa(int(t.remoteURI.Port())))
	conn, err := t.dialer.Dial(t.remoteURI.Scheme(), remote)
	if err != nil {
		return nil, errors.New("Unable to connect to remote endpoint: " + err.Error())
	}

	t.conn = conn.(*net.UDPConn)
	t.running.Store(true)

	if localURI == nil {
		t.localAddr = *t.conn.LocalAddr().(*net.UDPAddr)
		t.localURI = defn.DecodeURIString("udp://" + t.localAddr.String())
	}

	return t, nil
}

func (t *UnicastUDPTransport) String() string {
	return fmt.Sprintf("UnicastUDPTransport, FaceID=%d, RemoteURI=%s, LocalURI=%s", t.faceID, t.remoteURI, t.localURI)
}

func (t *UnicastUDPTransport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	t.persistency = persistency
	return true
}

func (t *UnicastUDPTransport) GetSendQueueSize() uint64 {
	rawConn, err := t.conn.SyscallConn()
	if err != nil {
		core.LogWarn(t, "Unable to get raw connection to get socket length: ", err)
	}
	return impl.SyscallGetSocketSendQueueSize(rawConn)
}

func (t *UnicastUDPTransport) sendFrame(frame []byte) {
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
	*t.expirationTime = time.Now().Add(udpLifetime)
}

func (t *UnicastUDPTransport) runReceive() {
	defer t.Close()

	err := readTlvStream(t.conn, func(b []byte) {
		t.nInBytes += uint64(len(b))
		*t.expirationTime = time.Now().Add(udpLifetime)
		t.linkService.handleIncomingFrame(b)
	}, func(err error) bool {
		// Ignore since UDP is a connectionless protocol
		// This happens if the other side is not listening (ICMP)
		return strings.Contains(err.Error(), "connection refused")
	})
	if err != nil && t.running.Load() {
		core.LogWarn(t, "Unable to read from socket (", err, ") - Face DOWN")
	}
}

func (t *UnicastUDPTransport) Close() {
	if t.running.Swap(false) {
		t.conn.Close()
	}
}
