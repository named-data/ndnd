package storage_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object/storage"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Verifies basic store operations (Put, Get with exact and prefix matching, Remove, and RemovePrefix) by inserting, retrieving, and deleting data under various name prefixes.
func testStoreBasic(t *testing.T, store ndn.Store) {
	name1, _ := enc.NameFromStr("/ndn/edu/ucla/test/packet/v1")
	name2, _ := enc.NameFromStr("/ndn/edu/ucla/test/packet/v5")
	name3, _ := enc.NameFromStr("/ndn/edu/ucla/test/packet/v9")
	name4, _ := enc.NameFromStr("/ndn/edu/ucla/test/packet/v2")
	name5, _ := enc.NameFromStr("/ndn/edu/arizona/test/packet/v11")

	wire1 := []byte{0x01, 0x02, 0x03}
	wire2 := []byte{0x04, 0x05, 0x06}
	wire3 := []byte{0x07, 0x08, 0x09}
	wire4 := []byte{0x0a, 0x0b, 0x0c}
	wire5 := []byte{0x0d, 0x0e, 0x0f}

	// test get when empty
	data, err := store.Get(name1, false)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)

	data, err = store.Get(name1, true)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)

	// put data
	require.NoError(t, store.Put(name1, wire1))

	// exact match with full name
	data, err = store.Get(name1, false)
	require.NoError(t, err)
	require.Equal(t, wire1, data)

	// prefix match with full name
	data, err = store.Get(name1, true)
	require.NoError(t, err)
	require.Equal(t, wire1, data)

	// exact match with partial name
	name1pfx := name1.Prefix(-1)
	data, err = store.Get(name1pfx, false)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)

	// prefix match with partial name
	data, err = store.Get(name1pfx, true)
	require.NoError(t, err)
	require.Equal(t, wire1, data)

	// insert second data under the same prefix
	require.NoError(t, store.Put(name2, wire2))

	// get data2 with exact match
	data, err = store.Get(name2, false)
	require.NoError(t, err)
	require.Equal(t, wire2, data)

	// get data2 with prefix match (newer version)
	data, err = store.Get(name1pfx, true)
	require.NoError(t, err)
	require.Equal(t, wire2, data)

	// put data3 under the same prefix (newest)
	require.NoError(t, store.Put(name3, wire3))
	data, err = store.Get(name1pfx, true)
	require.NoError(t, err)
	require.Equal(t, wire3, data)

	// make sure we can still get data 1
	data, err = store.Get(name1, false)
	require.NoError(t, err)
	require.Equal(t, wire1, data)

	// put data4 under the same prefix
	require.NoError(t, store.Put(name4, wire4))

	// check prefix still returns data 3
	data, err = store.Get(name1pfx, true)
	require.NoError(t, err)
	require.Equal(t, wire3, data)

	// put data5 under a different prefix
	require.NoError(t, store.Put(name5, wire5))
	data, err = store.Get(name5, false)
	require.NoError(t, err)
	require.Equal(t, wire5, data)

	// check prefix still returns data 3
	data, err = store.Get(name1pfx, true)
	require.NoError(t, err)
	require.Equal(t, wire3, data)

	// remove data 3
	require.NoError(t, store.Remove(name3))

	// check prefix now returns data 2
	data, err = store.Get(name1pfx, true)
	require.NoError(t, err)
	require.Equal(t, wire2, data)

	// clear subtree of name1
	require.NoError(t, store.RemovePrefix(name1pfx))

	// check prefix now returns no data
	data, err = store.Get(name1pfx, true)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)

	// check broad prefix returns data 5
	data, err = store.Get(name1.Prefix(2), true)
	require.NoError(t, err)
	require.Equal(t, wire5, data)
}

// (AI GENERATED DESCRIPTION): Tests inserting, retrieving, and removing Data packets in a Store by sequence‑number range, verifying correct behavior across normal, edge, and error scenarios.
func testStoreRemoveRange(t *testing.T, store ndn.Store) {
	seq1, _ := enc.NameFromStr("/ndn/edu/wustl/test/packet/seq=1")
	seq2, _ := enc.NameFromStr("/ndn/edu/wustl/test/packet/seq=2")
	seq3, _ := enc.NameFromStr("/ndn/edu/wustl/test/packet/seq=3")
	seq4, _ := enc.NameFromStr("/ndn/edu/wustl/test/packet/seq=4")
	seq5, _ := enc.NameFromStr("/ndn/edu/wustl/test/packet/seq=5")
	seq6, _ := enc.NameFromStr("/ndn/edu/wustl/test/packet/seq=6")
	seq7, _ := enc.NameFromStr("/ndn/edu/wustl/test/packet/seq=7")

	wire1 := []byte{0x01, 0x02, 0x03}
	wire2 := []byte{0x04, 0x05, 0x06}
	wire3 := []byte{0x07, 0x08, 0x09}
	wire4 := []byte{0x0a, 0x0b, 0x0c}
	wire5 := []byte{0x0d, 0x0e, 0x0f}
	wire6 := []byte{0x10, 0x11, 0x12}
	wire7 := []byte{0x13, 0x14, 0x15}

	// put data
	require.NoError(t, store.Put(seq1, wire1))
	require.NoError(t, store.Put(seq2, wire2))
	require.NoError(t, store.Put(seq3, wire3))
	require.NoError(t, store.Put(seq4, wire4))
	require.NoError(t, store.Put(seq5, wire5))
	require.NoError(t, store.Put(seq6, wire6))
	require.NoError(t, store.Put(seq7, wire7))

	// make sure we can get
	data, _ := store.Get(seq2, false)
	require.Equal(t, wire2, data)
	data, _ = store.Get(seq3, false)
	require.Equal(t, wire3, data)
	data, _ = store.Get(seq4, false)
	require.Equal(t, wire4, data)
	data, _ = store.Get(seq5, false)
	require.Equal(t, wire5, data)
	data, _ = store.Get(seq6, false)
	require.Equal(t, wire6, data)

	// remove range 3-5
	err := store.RemoveFlatRange(seq1.Prefix(-1), enc.NewSequenceNumComponent(3), enc.NewSequenceNumComponent(5))
	require.NoError(t, err)

	// check removed
	data, _ = store.Get(seq3, false)
	require.Equal(t, []byte(nil), data)
	data, _ = store.Get(seq4, false)
	require.Equal(t, []byte(nil), data)
	data, _ = store.Get(seq5, false)
	require.Equal(t, []byte(nil), data)

	// check 2 and 6 are still there
	data, _ = store.Get(seq2, false)
	require.Equal(t, wire2, data)
	data, _ = store.Get(seq6, false)
	require.Equal(t, wire6, data)

	// remove with a wrong range (differnt component types)
	err = store.RemoveFlatRange(seq1.Prefix(-1), enc.NewVersionComponent(1), enc.NewVersionComponent(10))
	require.NoError(t, err)

	// check nothing is removed
	data, _ = store.Get(seq2, false)
	require.Equal(t, wire2, data)
	data, _ = store.Get(seq6, false)
	require.Equal(t, wire6, data)

	// remove with first > last
	err = store.RemoveFlatRange(seq1.Prefix(-1), enc.NewSequenceNumComponent(10), enc.NewSequenceNumComponent(1))
	require.Error(t, err)

	// remove single element
	err = store.RemoveFlatRange(seq1.Prefix(-1), enc.NewSequenceNumComponent(2), enc.NewSequenceNumComponent(2))
	require.NoError(t, err)

	// check 2 is removed
	data, _ = store.Get(seq2, false)
	require.Equal(t, []byte(nil), data)
	data, _ = store.Get(seq6, false)
	require.Equal(t, wire6, data)

	// remove outer range
	err = store.RemoveFlatRange(seq1.Prefix(-1), enc.NewSequenceNumComponent(1), enc.NewSequenceNumComponent(6))
	require.NoError(t, err)

	// check 1 and 6 are removed
	data, _ = store.Get(seq1, false)
	require.Equal(t, []byte(nil), data)
	data, _ = store.Get(seq6, false)
	require.Equal(t, []byte(nil), data)

	// check 7 is still there
	data, _ = store.Get(seq7, false)
	require.Equal(t, wire7, data)
}

// (AI GENERATED DESCRIPTION): Tests that a Store correctly supports transactional operations by verifying that data added inside a transaction is invisible until commit, discarded on rollback, and that non‑transactional puts persist immediately.
func testStoreTxn(t *testing.T, store ndn.Store) {
	txname1, _ := enc.NameFromStr("/ndn/edu/memphis/test/packet/v1")
	txname2, _ := enc.NameFromStr("/ndn/edu/memphis/test/packet/v5")
	txname3, _ := enc.NameFromStr("/ndn/edu/memphis/test/packet/v9")

	wire1 := []byte{0x01, 0x02, 0x03}
	wire2 := []byte{0x04, 0x05, 0x06}
	wire3 := []byte{0x07, 0x08, 0x09}

	// put data1 and data2 under transaction
	// verify that neither can be seen
	tx, err := store.Begin()
	require.NoError(t, err)
	require.NoError(t, tx.Put(txname1, wire1))
	data, err := store.Get(txname1, false)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)

	require.NoError(t, tx.Put(txname2, wire2))
	data, err = store.Get(txname2, false)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)

	// commit transaction
	require.NoError(t, tx.Commit())

	// verify that both data can be seen
	data, err = store.Get(txname1, false)
	require.NoError(t, err)
	require.Equal(t, wire1, data)
	data, err = store.Get(txname2, false)
	require.NoError(t, err)
	require.Equal(t, wire2, data)

	// add data3 under transaction and rollback
	tx, err = store.Begin()
	require.NoError(t, err)
	require.NoError(t, tx.Put(txname3, wire3))
	data, err = store.Get(txname3, false)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)
	tx.Rollback()
	data, err = store.Get(txname3, false)
	require.NoError(t, err)
	require.Equal(t, []byte(nil), data)

	// insert data3 now without transaction
	require.NoError(t, store.Put(txname3, wire3))
	data, err = store.Get(txname3, false)
	require.NoError(t, err)
	require.Equal(t, wire3, data)
}

// (AI GENERATED DESCRIPTION): Runs a suite of unit tests to verify basic operations, range‑removal behavior, and transactional support for the in‑memory storage backend.
func TestMemoryStore(t *testing.T) {
	tu.SetT(t)
	store := storage.NewMemoryStore()
	testStoreBasic(t, store)
	testStoreRemoveRange(t, store)
	testStoreTxn(t, store)
}
