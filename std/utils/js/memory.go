//go:build js && wasm

package js

import "syscall/js"

// (AI GENERATED DESCRIPTION): Iterates over the map values and releases any js.Func instances it contains.
func ReleaseMap(m map[string]any) {
	for _, val := range m {
		if val, ok := val.(js.Func); ok {
			val.Release()
		}
	}
}
