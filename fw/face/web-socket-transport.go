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
	return fmt.Sprintf("WebSocketTransport, FaceID=%d, RemoteURI=%s, LocalURI=%s", t.faceID, t.remoteURI, t.localURI)
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
		core.LogWarn(t, "Attempted to send frame larger than MTU - DROP")
		return
	}

	e := t.c.WriteMessage(websocket.BinaryMessage, frame)
	if e != nil {
		core.LogWarn(t, "Unable to send on socket - DROP and Face DOWN")
		t.Close()
		return
	}

	t.nOutBytes += uint64(len(frame))
}

func (t *WebSocketTransport) runReceive() {
	defer t.Close()

	for {
		mt, message, e := t.c.ReadMessage()
		if e != nil {
			if websocket.IsCloseError(e) {
				// gracefully closed
			} else if websocket.IsUnexpectedCloseError(e) {
				core.LogInfo(t, "WebSocket closed unexpectedly (", e, ") - DROP and Face DOWN")
			} else {
				core.LogWarn(t, "Unable to read from WebSocket (", e, ") - DROP and Face DOWN")
			}
			return
		}

		if mt != websocket.BinaryMessage {
			core.LogWarn(t, "Ignored non-binary message")
			continue
		}

		if len(message) > defn.MaxNDNPacketSize {
			core.LogWarn(t, "Received too much data without valid TLV block - DROP")
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
