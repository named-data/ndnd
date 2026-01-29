/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/face/impl"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// UDPListener listens for incoming UDP unicast connections.
type UDPListener struct {
	conn     net.PacketConn
	localURI *defn.URI
	stopped  chan bool
}

// MakeUDPListener constructs a UDPListener.
func MakeUDPListener(localURI *defn.URI) (*UDPListener, error) {
	localURI.Canonize()
	if !localURI.IsCanonical() || (localURI.Scheme() != "udp4" && localURI.Scheme() != "udp6") {
		return nil, defn.ErrNotCanonical
	}

	l := new(UDPListener)
	l.localURI = localURI
	l.stopped = make(chan bool, 1)
	return l, nil
}

// (AI GENERATED DESCRIPTION): Returns a string representation of a UDPListener, showing its local URI.
func (l *UDPListener) String() string {
	return fmt.Sprintf("udp-listener (%s)", l.localURI)
}

// Run starts the UDP listener.
func (l *UDPListener) Run() {
	defer func() { l.stopped <- true }()

	// Create dialer and set reuse address option
	listenConfig := &net.ListenConfig{Control: impl.SyscallReuseAddr}

	// Create listener
	var remote string
	if l.localURI.Scheme() == "udp4" {
		remote = fmt.Sprintf("%s:%d", l.localURI.PathHost(), l.localURI.Port())
	} else {
		remote = fmt.Sprintf("[%s]:%d", l.localURI.Path(), l.localURI.Port())
	}

	// Start listening for incoming connections
	var err error
	l.conn, err = listenConfig.ListenPacket(context.Background(), l.localURI.Scheme(), remote)
	if err != nil {
		core.Log.Error(l, "Unable to start UDP listener", "err", err)
		return
	}

	// Run accept loop
	recvBuf := make([]byte, defn.MaxNDNPacketSize)
	for !core.ShouldQuit {
		readSize, remoteAddr, err := l.conn.ReadFrom(recvBuf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			core.Log.Warn(l, "Unable to read from socket", "err", err)
			return
		}

		// Construct remote URI
		remoteURI := defn.DecodeURIString(fmt.Sprintf("udp://%s", remoteAddr))
		if remoteURI == nil || !remoteURI.IsCanonical() {
			core.Log.Warn(l, "Unable to create face remote URI is not canonical", "uri", remoteURI)
			continue
		}

		// Check if frame received here is for an existing face.
		// This is probably because it was received too fast.
		// For now just drop the frame, ideally we should pass it to face.
		// If you call handleIncomingFrame() here, it will cause a race condition.
		if face := FaceTable.GetByURI(remoteURI); face != nil {
			core.Log.Trace(l, "Received frame for existing", "face", face)
			continue
		}

		// If frame received here, must be for new remote endpoint
		newTransport, err := MakeUnicastUDPTransport(remoteURI, l.localURI, spec_mgmt.PersistencyOnDemand)
		if err != nil {
			core.Log.Error(l, "Failed to create new unicast UDP transport", "err", err)
			continue
		}

		core.Log.Info(l, "Accepting new UDP face", "uri", newTransport.RemoteURI())
		MakeNDNLPLinkService(newTransport, MakeNDNLPLinkServiceOptions()).Run(recvBuf[:readSize])
	}
}

// (AI GENERATED DESCRIPTION): Closes the UDP connection and blocks until the listener’s goroutine has terminated.
func (l *UDPListener) Close() {
	if l.conn != nil {
		l.conn.Close()
		<-l.stopped
	}
}
