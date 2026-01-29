//go:build !tinygo

package face

import (
	"fmt"

	"github.com/gorilla/websocket"
	enc "github.com/named-data/ndnd/std/encoding"
)

type WebSocketFace struct {
	baseFace
	url  string
	conn *websocket.Conn
}

// (AI GENERATED DESCRIPTION): Creates a new WebSocketFace, initializing its base face with the supplied local flag and assigning the given WebSocket URL.
func NewWebSocketFace(url string, local bool) *WebSocketFace {
	return &WebSocketFace{
		baseFace: newBaseFace(local),
		url:      url,
	}
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable string describing the WebSocketFace, formatted as “websocket‑face (URL)”.
func (f *WebSocketFace) String() string {
	return fmt.Sprintf("websocket-face (%s)", f.url)
}

// (AI GENERATED DESCRIPTION): Opens a WebSocket connection for the face, initializes the connection, sets the face state to up, and starts a goroutine to receive packets.
func (f *WebSocketFace) Open() error {
	if f.IsRunning() {
		return fmt.Errorf("face is already running")
	}

	if f.onError == nil || f.onPkt == nil {
		return fmt.Errorf("face callbacks are not set")
	}

	c, _, err := websocket.DefaultDialer.Dial(f.url, nil)
	if err != nil {
		return err
	}

	f.conn = c
	f.setStateUp()
	go f.receive()

	return nil
}

// (AI GENERATED DESCRIPTION): Closes the WebSocket face by marking it as closed and terminating the underlying connection if it hasn't already been closed.
func (f *WebSocketFace) Close() error {
	if f.setStateClosed() {
		return f.conn.Close()
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Sends the given packet over the WebSocket connection if the face is running, otherwise returns an error.
func (f *WebSocketFace) Send(pkt enc.Wire) error {
	if !f.IsRunning() {
		return fmt.Errorf("face is not running")
	}

	return f.conn.WriteMessage(websocket.BinaryMessage, pkt.Join())
}

// (AI GENERATED DESCRIPTION): Continuously reads binary messages from the WebSocket, processes each as a packet via `onPkt`, handles any read errors, and switches the face to the down state when it stops.
func (f *WebSocketFace) receive() {
	defer f.setStateDown()

	for f.IsRunning() {
		messageType, pkt, err := f.conn.ReadMessage()
		if err != nil {
			if f.IsRunning() {
				f.onError(err)
			}
			return
		}

		if messageType != websocket.BinaryMessage {
			continue
		}

		f.onPkt(pkt)
	}
}
