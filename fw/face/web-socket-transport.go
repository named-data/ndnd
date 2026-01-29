//go:build !tinygo

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

// (AI GENERATED DESCRIPTION): Creates a new WebSocketTransport for the given websocket connection, initializing its remote URI, determining if it is local or non‑local, setting up base transport parameters, and marking the transport as running.
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

// (AI GENERATED DESCRIPTION): Returns a formatted string summarizing the WebSocket transport, including its face ID, remote URI, and local URI.
func (t *WebSocketTransport) String() string {
	return fmt.Sprintf("web-socket-transport (faceid=%d remote=%s local=%s)", t.faceID, t.remoteURI, t.localURI)
}

// (AI GENERATED DESCRIPTION): Returns true if the supplied persistency mode is PersistencyOnDemand; otherwise returns false.
func (t *WebSocketTransport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	return persistency == spec_mgmt.PersistencyOnDemand
}

// (AI GENERATED DESCRIPTION): Returns the current number of packets queued for transmission on the WebSocket transport.
func (t *WebSocketTransport) GetSendQueueSize() uint64 {
	return 0
}

// (AI GENERATED DESCRIPTION): Sends a binary frame over the WebSocket transport if it is active, enforcing MTU limits, logging write errors and closing the face on failure, while updating the outbound byte counter.
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

// (AI GENERATED DESCRIPTION): runReceive continuously reads binary frames from the WebSocket, discarding non‑binary or oversized messages, updating inbound byte counters, forwarding valid frames to the link service for processing, and gracefully handling read errors or connection closure.
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

// (AI GENERATED DESCRIPTION): Stops the WebSocketTransport from running and closes the underlying WebSocket connection.
func (t *WebSocketTransport) Close() {
	t.running.Store(false)
	t.c.Close()
}
