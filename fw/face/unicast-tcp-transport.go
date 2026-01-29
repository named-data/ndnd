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
	"strconv"
	"time"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/face/impl"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/utils"
	ndn_io "github.com/named-data/ndnd/std/utils/io"
)

// URI to use when the local URI is unknown.
var StubTcpUri = defn.DecodeURIString("tcp://127.0.0.1:0")

// UnicastTCPTransport is a unicast TCP transport.
type UnicastTCPTransport struct {
	transportBase

	dialer     *net.Dialer
	conn       *net.TCPConn
	localAddr  net.TCPAddr
	remoteAddr net.TCPAddr

	// Permanent face reconnection
	rechan chan bool
	closed bool // (permanently)
}

// Makes an outgoing unicast TCP transport.
func MakeUnicastTCPTransport(
	remoteURI *defn.URI,
	localURI *defn.URI,
	persistency spec_mgmt.Persistency,
) (*UnicastTCPTransport, error) {
	// Validate URIs.
	if !remoteURI.IsCanonical() ||
		(remoteURI.Scheme() != "tcp4" && remoteURI.Scheme() != "tcp6") {
		return nil, defn.ErrNotCanonical
	}
	if localURI != nil {
		return nil, fmt.Errorf("do not specify localURI for TCP")
	}

	// Construct transport
	t := new(UnicastTCPTransport)
	t.makeTransportBase(remoteURI, localURI, persistency, defn.NonLocal, defn.PointToPoint, defn.MaxNDNPacketSize)
	t.expirationTime = utils.IdPtr(time.Now().Add(CfgTCPLifetime()))
	t.rechan = make(chan bool, 2)

	// Set scope
	ip := net.ParseIP(remoteURI.Path())
	if ip.IsLoopback() {
		t.scope = defn.Local
	} else {
		t.scope = defn.NonLocal
	}

	// Set local and remote addresses
	t.localAddr.Port = CfgTCPUnicastPort()
	t.remoteAddr.IP = net.ParseIP(remoteURI.Path())
	t.remoteAddr.Port = int(remoteURI.Port())

	// Configure dialer so we can allow address reuse
	// Fix: for TCP we shouldn't specify the local address. Instead, we should obtain it from system.
	// Though it succeeds in Windows and MacOS, Linux does not allow this.
	t.dialer = &net.Dialer{Control: impl.SyscallReuseAddr}

	// Do not attempt to connect here at all, since it blocks the main thread
	// The cost is that we can't compute the localUri here
	// We will attempt to connect in the receive loop instead

	// Fake for filling up the response
	t.localURI = StubTcpUri

	return t, nil
}

// Accept an incoming unicast TCP transport.
func AcceptUnicastTCPTransport(
	remoteConn net.Conn,
	localURI *defn.URI,
	persistency spec_mgmt.Persistency,
) (*UnicastTCPTransport, error) {
	// Construct remote URI
	remoteAddr := remoteConn.RemoteAddr()
	remoteURI := defn.DecodeURIString(fmt.Sprintf("tcp://%s", remoteAddr))

	// Construct transport
	t := new(UnicastTCPTransport)
	t.makeTransportBase(remoteURI, localURI, persistency, defn.NonLocal, defn.PointToPoint, defn.MaxNDNPacketSize)
	t.expirationTime = utils.IdPtr(time.Now().Add(CfgTCPLifetime()))
	t.rechan = make(chan bool, 1)

	conn, success := remoteConn.(*net.TCPConn)
	if !success {
		core.Log.Error(t, "Specified connection is not a net.TCPConn", "conn", remoteConn)
		return nil, fmt.Errorf("specified connection is not a net.TCPConn")
	}
	t.running.Store(true)

	// Set connection
	t.setConn(conn)

	// Set remote address
	t.remoteAddr.IP = net.ParseIP(remoteURI.Path())
	t.remoteAddr.Port = int(remoteURI.Port())

	// Override local address if specified
	if localURI != nil {
		t.localAddr.IP = net.ParseIP(localURI.Path())
		t.localAddr.Port = int(localURI.Port())
	}

	// Set scope
	ip := net.ParseIP(remoteURI.Path())
	if ip.IsLoopback() {
		t.scope = defn.Local
	} else {
		t.scope = defn.NonLocal
	}

	return t, nil
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable string describing the unicast‑TCP transport, including its face ID, remote URI, and local URI.
func (t *UnicastTCPTransport) String() string {
	return fmt.Sprintf("unicast-tcp-transport (faceid=%d remote=%s local=%s)", t.faceID, t.remoteURI, t.localURI)
}

// (AI GENERATED DESCRIPTION): Sets the persistency mode for the UnicastTCPTransport and reports success.
func (t *UnicastTCPTransport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	t.persistency = persistency
	return true
}

// (AI GENERATED DESCRIPTION): Retrieves the number of bytes currently queued in the underlying TCP socket’s send buffer for this transport.
func (t *UnicastTCPTransport) GetSendQueueSize() uint64 {
	rawConn, err := t.conn.SyscallConn()
	if err != nil {
		core.Log.Warn(t, "Unable to get raw connection to get socket length", "err", err)
	}
	return impl.SyscallGetSocketSendQueueSize(rawConn)
}

// Set the connection and params.
func (t *UnicastTCPTransport) setConn(conn *net.TCPConn) {
	t.conn = conn
	t.localAddr = *t.conn.LocalAddr().(*net.TCPAddr)
	t.localURI = defn.DecodeURIString(fmt.Sprintf("tcp://%s", &t.localAddr))
}

// Attempt to reconnect to the remote transport.
func (t *UnicastTCPTransport) reconnect() {
	// Shut down the existing socket
	if t.conn != nil {
		t.conn.Close()
		t.localURI = StubTcpUri
	}

	// Number of attempts we have made so far
	attempt := 0

	// Keep trying to reconnect until successful
	// If the transport is not permanent, do not attempt to restart
	// Do this inside the loop to account for changes to persistency
	for {
		attempt++

		// If there is no connection, this is the initial attempt to
		// connect for any face, so we will continue regardless
		// However, make only one attempt to connect for non-permanent faces
		if !(t.conn == nil && attempt == 1) {
			// Do not continue if the transport is not permanent or closed
			if t.Persistency() != spec_mgmt.PersistencyPermanent || t.closed {
				t.rechan <- false // do not continue
				return
			}
		}

		// Restart socket for permanent transport
		remote := net.JoinHostPort(t.remoteURI.Path(), strconv.Itoa(int(t.remoteURI.Port())))
		conn, err := t.dialer.Dial(t.remoteURI.Scheme(), remote)
		if err != nil {
			core.Log.Warn(t, "Unable to connect to remote endpoint", "err", err, "attempt", attempt)
			time.Sleep(time.Duration(core.C.Faces.Tcp.ReconnectInterval) * time.Second)
			continue
		}

		// If the transport was closed while we were trying to reconnect,
		// close the new connection and return without notifying
		if t.closed {
			conn.Close()
			return
		}

		// Connected to remote again
		t.setConn(conn.(*net.TCPConn))
		t.rechan <- true // continue
		return
	}
}

// (AI GENERATED DESCRIPTION): Sends a frame over the unicast TCP connection, ensuring it does not exceed the MTU, updating outbound byte statistics, resetting the socket’s expiration timer, and closing the connection if the write fails.
func (t *UnicastTCPTransport) sendFrame(frame []byte) {
	if !t.running.Load() {
		return
	}

	if len(frame) > t.MTU() {
		core.Log.Warn(t, "Attempted to send frame larger than MTU")
		return
	}

	_, err := t.conn.Write(frame)
	if err != nil {
		core.Log.Warn(t, "Unable to send on socket")
		t.CloseConn() // receive might restart if needed
		return
	}

	t.nOutBytes += uint64(len(frame))
	*t.expirationTime = time.Now().Add(CfgTCPLifetime())
}

// (AI GENERATED DESCRIPTION): Runs the receive loop for a UnicastTCPTransport, reading TLV frames from the socket, dispatching them to the link service, and automatically reconnecting or closing the face depending on connection state and persistency.
func (t *UnicastTCPTransport) runReceive() {
	defer t.Close()

	for {
		// The connection can be nil if the initial connection attempt
		// failed for a persistent face. In that case we will reconnect.
		if t.conn != nil {
			err := ndn_io.ReadTlvStream(t.conn, func(b []byte) bool {
				t.nInBytes += uint64(len(b))
				*t.expirationTime = time.Now().Add(CfgTCPLifetime())
				t.linkService.handleIncomingFrame(b)
				return true
			}, nil)
			if err == nil && t.Persistency() != spec_mgmt.PersistencyPermanent {
				break // EOF
			}
			if t.closed {
				break // permanent close
			}

			core.Log.Warn(t, "Unable to read from socket - Face DOWN", "err", err)
		}

		// Persistent faces will reconnect, otherwise close
		go t.reconnect()
		if !<-t.rechan {
			return // do not continue
		}

		core.Log.Info(t, "Connected socket - Face UP")
		t.running.Store(true)
	}
}

// Close the inner connection if running without closing the transport.
func (t *UnicastTCPTransport) CloseConn() {
	if t.running.Swap(false) {
		t.conn.Close()
	}
}

// Close the connection permanently - this will not attempt to reconnect.
func (t *UnicastTCPTransport) Close() {
	t.closed = true
	t.rechan <- false
	t.CloseConn()
}
