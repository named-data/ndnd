//go:build !js

package merklelog

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBadgerStoreRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "badger")
	store, err := NewBadgerStore(path)
	require.NoError(t, err)

	tree, entries, expectedRoot := populateStore(t, store)
	require.Equal(t, uint64(len(entries)), tree.Size())
	require.NoError(t, store.Close())

	store, err = NewBadgerStore(path)
	require.NoError(t, err)
	defer store.Close()
	assertRestoredTree(t, store, entries, expectedRoot)
}

func TestStoreStateEncoding(t *testing.T) {
	tree := NewTree()
	for size := 0; size <= 16; size++ {
		state := tree.storeState()
		encoded, err := encodeStoreState(state)
		require.NoError(t, err)
		decoded, err := decodeStoreState(encoded)
		require.NoError(t, err)
		require.True(t, equalStoreState(state, decoded))

		if size < 16 {
			_, err = tree.Append(testEntryWire(size))
			require.NoError(t, err)
		}
	}
}
