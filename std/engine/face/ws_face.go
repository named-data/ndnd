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

func NewWebSocketFace(url string, local bool) *WebSocketFace {
	return &WebSocketFace{
		baseFace: newBaseFace(local),
		url:      url,
	}
}

func (f *WebSocketFace) String() string {
	return fmt.Sprintf("websocket-face (%s)", f.url)
}

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

func (f *WebSocketFace) Close() error {
	if f.setStateClosed() {
		return f.conn.Close()
	}

	return nil
}

func (f *WebSocketFace) Send(pkt enc.Wire) error {
	if !f.IsRunning() {
		return fmt.Errorf("face is not running")
	}

	return f.conn.WriteMessage(websocket.BinaryMessage, pkt.Join())
}

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
