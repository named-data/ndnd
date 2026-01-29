//go:build js && wasm

package face

import (
	"fmt"
	"syscall/js"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	jsutil "github.com/named-data/ndnd/std/utils/js"
)

type WasmSimFace struct {
	baseFace
	gosim js.Value
}

// (AI GENERATED DESCRIPTION): Initializes a new WasmSimFace with its base face configured for simulation mode and a null simulation engine.
func NewWasmSimFace() *WasmSimFace {
	return &WasmSimFace{
		baseFace: newBaseFace(true),
		gosim:    js.Null(),
	}
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable identifier for a `WasmSimFace`, always yielding the string `"wasm-sim-face"`.
func (f *WasmSimFace) String() string {
	return "wasm-sim-face"
}

// (AI GENERATED DESCRIPTION): Initializes and opens the WASM simulation face by registering the packet‑receive callback and marking its state up, while verifying that the error and packet callbacks are set and the face is not already running.
func (f *WasmSimFace) Open() error {
	if f.onError == nil || f.onPkt == nil {
		return fmt.Errorf("face callbacks are not set")
	}

	if !f.gosim.IsNull() {
		return fmt.Errorf("face is already running")
	}

	// It seems now Go cannot handle exceptions thrown by JS
	f.gosim = js.Global().Get("gondnsim")
	f.gosim.Call("setRecvPktCallback", js.FuncOf(f.receive))

	log.Info(f, "Face opened")
	f.setStateUp()

	return nil
}

// (AI GENERATED DESCRIPTION): Closes the WasmSimFace by marking its state closed, disabling its packet‑receive callback, and nullifying the Go simulation reference.
func (f *WasmSimFace) Close() error {
	if f.setStateClosed() {
		f.gosim.Call("setRecvPktCallback", js.FuncOf(func(this js.Value, args []js.Value) any {
			return nil
		}))
		f.gosim = js.Null()
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Sends a packet to the wasm simulation by copying its bytes into a JavaScript Uint8Array and invoking the simulation’s “sendPkt” method.
func (f *WasmSimFace) Send(pkt enc.Wire) error {
	if !f.IsRunning() {
		return fmt.Errorf("face is not running")
	}

	l := pkt.Length()
	arr := js.Global().Get("Uint8Array").New(int(l))
	js.CopyBytesToJS(arr, pkt.Join())
	f.gosim.Call("sendPkt", arr)

	return nil
}

// (AI GENERATED DESCRIPTION): Receives a packet sent from JavaScript, converts the JS array to a Go byte slice, and forwards it to the face’s packet‑processing callback.
func (f *WasmSimFace) receive(this js.Value, args []js.Value) any {
	f.onPkt(jsutil.JsArrayToSlice(args[0]))
	return nil
}
