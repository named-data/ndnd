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

func NewWasmWsFace(url string, local bool) *WasmWsFace {
	return &WasmWsFace{
		baseFace: newBaseFace(local),
		url:      url,
		conn:     js.Null(),
	}
}

func (f *WasmWsFace) String() string {
	return fmt.Sprintf("wasm-ws-face (%s)", f.url)
}

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

func (f *WasmWsFace) Close() error {
	if f.setStateClosed() {
		f.closed.Store(true)
		f.conn.Call("close")
		f.conn = js.Null()
	}

	return nil
}

func (f *WasmWsFace) Send(pkt enc.Wire) error {
	if !f.IsRunning() {
		return nil
	}

	arr := jsutil.SliceToJsArray(pkt.Join())
	f.conn.Call("send", arr)

	return nil
}

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

func (f *WasmWsFace) receive(this js.Value, args []js.Value) any {
	event := args[0]
	data := event.Get("data")
	f.onPkt(jsutil.JsArrayToSlice(data))
	return nil
}
