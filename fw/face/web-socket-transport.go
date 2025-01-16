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

	"github.com/gorilla/websocket"
	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// WebSocketTransport communicates with web applications via WebSocket.
type WebSocketTransport struct {
	transportBase
	c *websocket.Conn
}

func NewWebSocketTransport(localURI *defn.URI, c *websocket.Conn) (t *WebSocketTransport) {
	remoteURI := defn.MakeWebSocketClientFaceURI(c.RemoteAddr())

	scope := defn.NonLocal
	ip := net.ParseIP(remoteURI.PathHost())
	if ip != nil && ip.IsLoopback() {
		scope = defn.Local
	}

	t = &WebSocketTransport{c: c}
	t.makeTransportBase(remoteURI, localURI, spec_mgmt.PersistencyOnDemand, scope, defn.PointToPoint, defn.MaxNDNPacketSize)
	t.running.Store(true)

	return t
}

func (t *WebSocketTransport) String() string {
	return fmt.Sprintf("web-socket-transport (faceid=%d remote=%s local=%s)", t.faceID, t.remoteURI, t.localURI)
}

func (t *WebSocketTransport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	return persistency == spec_mgmt.PersistencyOnDemand
}

func (t *WebSocketTransport) GetSendQueueSize() uint64 {
	return 0
}

func (t *WebSocketTransport) sendFrame(frame []byte) {
	if !t.running.Load() {
		return
	}

	if len(frame) > t.MTU() {
		core.Log.Warn(t, "Attempted to send frame larger than MTU")
		return
	}

	e := t.c.WriteMessage(websocket.BinaryMessage, frame)
	if e != nil {
		core.Log.Warn(t, "Unable to send on socket - Face DOWN")
		t.Close()
		return
	}

	t.nOutBytes += uint64(len(frame))
}

func (t *WebSocketTransport) runReceive() {
	defer t.Close()

	for {
		mt, message, err := t.c.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err) {
				// gracefully closed
			} else if websocket.IsUnexpectedCloseError(err) {
				core.Log.Info(t, "WebSocket closed unexpectedly - DROP and Face DOWN", "err", err)
			} else {
				core.Log.Warn(t, "Unable to read from WebSocket - DROP and Face DOWN", "err", err)
			}
			return
		}

		if mt != websocket.BinaryMessage {
			core.Log.Warn(t, "Ignored non-binary message")
			continue
		}

		if len(message) > defn.MaxNDNPacketSize {
			core.Log.Warn(t, "Received too much data without valid TLV block")
			continue
		}

		t.nInBytes += uint64(len(message))
		t.linkService.handleIncomingFrame(message)
	}
}

func (t *WebSocketTransport) Close() {
	t.running.Store(false)
	t.c.Close()
}
