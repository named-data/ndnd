//go:build js && wasm

package face

import (
	"fmt"
	"sync/atomic"
	"syscall/js"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	jsutil "github.com/named-data/ndnd/std/utils/js"
)

type WasmWsFace struct {
	baseFace
	url    string
	conn   js.Value
	closed atomic.Bool
}

// (AI GENERATED DESCRIPTION): Creates a new Wasm WebSocket face, initializing its base face with the given local flag, setting the URL, and starting with no active connection.
func NewWasmWsFace(url string, local bool) *WasmWsFace {
	return &WasmWsFace{
		baseFace: newBaseFace(local),
		url:      url,
		conn:     js.Null(),
	}
}

// (AI GENERATED DESCRIPTION): Returns a string representation of a Wasm WebSocket face, formatted as "wasm‑ws‑face (<url>)".
func (f *WasmWsFace) String() string {
	return fmt.Sprintf("wasm-ws-face (%s)", f.url)
}

// (AI GENERATED DESCRIPTION): Opens the Wasm WebSocket face, initializing the required callbacks and starting the underlying connection if it is not already running.
func (f *WasmWsFace) Open() error {
	if f.IsRunning() {
		return nil
	}

	if f.onError == nil || f.onPkt == nil {
		return fmt.Errorf("face callbacks are not set")
	}

	f.closed.Store(false)
	f.reopen()

	return nil
}

// (AI GENERATED DESCRIPTION): Closes the WebSocket face by marking it as closed, shutting down the underlying JavaScript connection, and clearing the connection reference.
func (f *WasmWsFace) Close() error {
	if f.setStateClosed() {
		f.closed.Store(true)
		f.conn.Call("close")
		f.conn = js.Null()
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Sends a packet over the WebSocket connection if the face is running, converting the packet’s bytes to a JavaScript array before invoking `conn.send`.
func (f *WasmWsFace) Send(pkt enc.Wire) error {
	if !f.IsRunning() {
		return nil
	}

	arr := jsutil.SliceToJsArray(pkt.Join())
	f.conn.Call("send", arr)

	return nil
}

// (AI GENERATED DESCRIPTION): Reestablishes the WebSocket connection by creating a new socket, attaching handlers for message, open, error, and close events, and scheduling automatic reconnects on failure, but only if the face is neither closed nor already running.
func (f *WasmWsFace) reopen() {
	if f.closed.Load() || f.IsRunning() {
		return
	}

	// It seems now Go cannot handle exceptions thrown by JS
	conn := js.Global().Get("WebSocket").New(f.url)
	conn.Set("binaryType", "arraybuffer")

	conn.Call("addEventListener", "message", js.FuncOf(f.receive))
	conn.Call("addEventListener", "open", js.FuncOf(func(this js.Value, args []js.Value) any {
		f.conn = conn
		f.setStateUp()
		return nil
	}))
	conn.Call("addEventListener", "error", js.FuncOf(func(this js.Value, args []js.Value) any {
		f.setStateDown()
		f.conn = js.Null()
		if !f.closed.Load() {
			time.AfterFunc(4*time.Second, func() { f.reopen() })
		}
		return nil
	}))
	conn.Call("addEventListener", "close", js.FuncOf(func(this js.Value, args []js.Value) any {
		f.setStateDown()
		f.conn = js.Null()
		if !f.closed.Load() {
			time.AfterFunc(4*time.Second, func() { f.reopen() })
		}
		return nil
	}))
}

// (AI GENERATED DESCRIPTION): Handles incoming WebSocket events by extracting the event data payload, converting it to a Go byte slice, and passing it to the face’s packet handler.
func (f *WasmWsFace) receive(this js.Value, args []js.Value) any {
	event := args[0]
	data := event.Get("data")
	f.onPkt(jsutil.JsArrayToSlice(data))
	return nil
}
