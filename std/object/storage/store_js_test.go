//go:build js && wasm

package storage_test

import (
	"syscall/js"
	"testing"

	"github.com/named-data/ndnd/std/object/storage"
	tu "github.com/named-data/ndnd/std/utils/testutils"
)

// (AI GENERATED DESCRIPTION): Runs unit tests on a JavaScript-backed store: it creates a `JsStore` from the global JS variable, then executes basic store operation tests and key‑range removal tests.
func TestJsStore(t *testing.T) {
	tu.SetT(t)
	store := storage.NewJsStore(js.Global().Get("_ndnd_store_js"))
	testStoreBasic(t, store)
	testStoreRemoveRange(t, store)
	// testStoreTxn(t, store)
}
