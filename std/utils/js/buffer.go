//go:build js && wasm

package js

import "syscall/js"

var arrayBuffer = js.Global().Get("ArrayBuffer")
var uint8Array = js.Global().Get("Uint8Array")

// (AI GENERATED DESCRIPTION): Converts a Go byte slice into a JavaScript Uint8Array, enabling the byte data to be passed to JavaScript from WebAssembly.
func SliceToJsArray(slice []byte) js.Value {
	jsSlice := uint8Array.New(len(slice))
	js.CopyBytesToJS(jsSlice, slice)
	return jsSlice
}

// (AI GENERATED DESCRIPTION): Converts a JavaScript ArrayBuffer or Uint8Array into a Go `[]byte` slice by copying its bytes.
func JsArrayToSlice(jsArray js.Value) []byte {
	if jsArray.InstanceOf(arrayBuffer) {
		jsArray = uint8Array.New(jsArray)
	}

	slice := make([]byte, jsArray.Get("byteLength").Int())
	js.CopyBytesToGo(slice, jsArray)
	return slice
}
