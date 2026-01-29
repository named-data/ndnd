//go:build js && wasm

package storage

import (
	"bytes"
	"fmt"
	"syscall/js"

	"unsafe"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/priority_queue"
	"github.com/named-data/ndnd/std/utils"
	jsutil "github.com/named-data/ndnd/std/utils/js"
)

type JsStore struct {
	api js.Value
	tx  int

	cache     map[string]*priority_queue.Item[jsStoreTuple, int]
	cachePq   *priority_queue.Queue[jsStoreTuple, int]
	cacheSize int
	cacheP    *int
}

type jsStoreTuple struct {
	name string
	wire []byte
}

// (AI GENERATED DESCRIPTION): Creates a new JsStore instance, initializing its API reference, transaction counter, an empty priority‑queue cache of size 8192, and related bookkeeping fields.
func NewJsStore(api js.Value) *JsStore {
	return &JsStore{
		api: api,
		tx:  0,

		cache:     make(map[string]*priority_queue.Item[jsStoreTuple, int], 8192),
		cachePq:   utils.IdPtr(priority_queue.New[jsStoreTuple, int]()),
		cacheSize: 8192, // approx 64MB
		cacheP:    utils.IdPtr(0),
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the wire data for a given name (or name prefix) from the JavaScript‑backed store, caching any returned items for faster subsequent lookups.
func (s *JsStore) Get(name enc.Name, prefix bool) ([]byte, error) {
	*s.cacheP++ // priority

	// JS is single-threaded, so no need to lock
	nameTlvStr := name.TlvStr()
	if item, ok := s.cache[nameTlvStr]; ok {
		s.cachePq.UpdatePriority(item, *s.cacheP)
		return item.Value().wire, nil
	}

	name_js := jsutil.SliceToJsArray(name.BytesInner())

	// Preload from the store - hint for the last item in page
	var last_hint_js js.Value = js.Undefined()
	if seg := name.At(-1); !prefix && seg.Typ == enc.TypeSegmentNameComponent {
		lastHint := name.Prefix(-1).
			Append(enc.NewSegmentComponent(seg.NumberVal() + 63)). // inclusive
			BytesInner()
		last_hint_js = jsutil.SliceToJsArray(lastHint)
	}

	// [Uint8Array, Uint8Array][]
	page, err := jsutil.Await(s.api.Call("get", name_js, prefix, last_hint_js))
	if err != nil {
		return nil, err
	}
	pageSize := page.Get("length").Int()

	// Preload all items in the page
	for i := range pageSize {
		item := page.Index(i)
		name := jsutil.JsArrayToSlice(item.Index(0))
		wire := jsutil.JsArrayToSlice(item.Index(1))

		tlvstr := unsafe.String(unsafe.SliceData(name), len(name)) // no copy
		s.insertCache(tlvstr, wire)

		// If prefix is set, exactly one item should be returned
		if prefix {
			return wire, nil
		}
	}

	if item, ok := s.cache[nameTlvStr]; ok {
		return item.Value().wire, nil
	}

	return nil, nil
}

// (AI GENERATED DESCRIPTION): Stores a data packet in the JavaScript-backed store under the given name, awaiting the operation when in transaction mode, and updates the in‑memory cache with the stored item.
func (s *JsStore) Put(name enc.Name, wire []byte) error {
	tlvBytes := name.BytesInner()
	name_js := jsutil.SliceToJsArray(tlvBytes)
	wire_js := jsutil.SliceToJsArray(wire)

	// This cannot be awaited because it will block the main thread
	// and deadlock if called from a js function
	promise := s.api.Call("put", name_js, wire_js, s.tx) // yolo
	if s.tx != 0 {
		jsutil.Await(promise)
	}

	// Cache the item
	tlvStr := unsafe.String(unsafe.SliceData(tlvBytes), len(tlvBytes)) // no copy
	s.insertCache(tlvStr, wire)

	return nil
}

// (AI GENERATED DESCRIPTION): Removes the entry with the specified name from the underlying store, without clearing any cached data.
func (s *JsStore) Remove(name enc.Name) error {
	// This does not evict the cache, but that's fine.
	// Applications should not rely on the cache for correctness.

	name_js := jsutil.SliceToJsArray(name.BytesInner())
	s.api.Call("remove", name_js, false)
	return nil
}

// (AI GENERATED DESCRIPTION): Removes all entries in the JavaScript store whose names begin with the specified prefix.
func (s *JsStore) RemovePrefix(prefix enc.Name) error {
	name_js := jsutil.SliceToJsArray(prefix.BytesInner())
	s.api.Call("remove", name_js, true)
	return nil
}

// (AI GENERATED DESCRIPTION): Removes all entries whose keys lie between the concatenated prefix+first component and prefix+last component in the underlying key‑value store.
func (s *JsStore) RemoveFlatRange(prefix enc.Name, first enc.Component, last enc.Component) error {
	firstKey := prefix.Append(first).BytesInner()
	lastKey := prefix.Append(last).BytesInner()
	if bytes.Compare(firstKey, lastKey) > 0 {
		return fmt.Errorf("first key is greater than last key")
	}

	first_js := jsutil.SliceToJsArray(firstKey)
	last_js := jsutil.SliceToJsArray(lastKey)
	s.api.Call("remove_flat_range", first_js, last_js)
	return nil
}

// (AI GENERATED DESCRIPTION): Begins a new transaction in the JsStore by calling the underlying API's “begin” method and returns a new JsStore instance.
func (s *JsStore) Begin() (ndn.Store, error) {
	return &JsStore{
		api:       s.api,
		tx:        s.api.Call("begin").Int(),
		cache:     s.cache,
		cachePq:   s.cachePq,
		cacheSize: s.cacheSize,
		cacheP:    s.cacheP,
	}, nil
}

// (AI GENERATED DESCRIPTION): Commits the current transaction to the underlying store via the JavaScript API and waits for its completion.
func (s *JsStore) Commit() error {
	jsutil.Await(s.api.Call("commit", s.tx))
	return nil
}

// (AI GENERATED DESCRIPTION): Rolls back the current transaction by invoking the JavaScript API’s `rollback` method on the transaction and waiting for completion.
func (s *JsStore) Rollback() error {
	jsutil.Await(s.api.Call("rollback", s.tx))
	return nil
}

// (AI GENERATED DESCRIPTION): Clears the JsStore's cache by repeatedly popping items from the priority queue and deleting their corresponding entries from the internal cache map.
func (s *JsStore) ClearCache() {
	for s.cachePq.Len() > 0 {
		k := s.cachePq.Pop()
		delete(s.cache, k.name)
	}
}

// (AI GENERATED DESCRIPTION): Inserts a new entry into the JsStore’s LRU cache for the given TLV string and wire data, evicting the least‑recently‑used item when the cache size limit is exceeded.
func (s *JsStore) insertCache(tlvstr string, wire []byte) {
	if s.cache[tlvstr] == nil {
		s.cache[tlvstr] = s.cachePq.Push(jsStoreTuple{
			name: tlvstr,
			wire: wire,
		}, *s.cacheP)

		// Evict the least recently used item
		if s.cachePq.Len() > s.cacheSize {
			delete(s.cache, s.cachePq.Pop().name)
		}
	}
}
