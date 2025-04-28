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

func NewWasmSimFace() *WasmSimFace {
	return &WasmSimFace{
		baseFace: newBaseFace(true),
		gosim:    js.Null(),
	}
}

func (f *WasmSimFace) String() string {
	return "wasm-sim-face"
}

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

func (f *WasmSimFace) Close() error {
	if f.setStateClosed() {
		f.gosim.Call("setRecvPktCallback", js.FuncOf(func(this js.Value, args []js.Value) any {
			return nil
		}))
		f.gosim = js.Null()
	}

	return nil
}

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

func (f *WasmSimFace) receive(this js.Value, args []js.Value) any {
	f.onPkt(jsutil.JsArrayToSlice(args[0]))
	return nil
}
