package merklelog

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryStoreRestart(t *testing.T) {
	store := NewMemoryStore()
	testStoreRestart(t, store, func() (Store, error) {
		return store, nil
	})
}

func TestStoreRejectsStaleWriterWithoutMutatingTree(t *testing.T) {
	store := NewMemoryStore()
	first, err := OpenTree(store)
	require.NoError(t, err)
	stale, err := OpenTree(store)
	require.NoError(t, err)

	_, err = first.Append(testEntryWire(0))
	require.NoError(t, err)
	staleRoot := stale.Root()
	_, err = stale.Append(testEntryWire(1))
	require.ErrorIs(t, err, ErrStoreStateChanged)
	require.Equal(t, uint64(0), stale.Size())
	require.Equal(t, staleRoot, stale.Root())
	_, found := stale.Lookup(testDataHash(1))
	require.False(t, found)
}

func TestStoreFailureDoesNotMutateTree(t *testing.T) {
	expectedErr := errors.New("write failed")
	store := &failingStore{
		Store: NewMemoryStore(),
		err:   expectedErr,
	}
	tree, err := OpenTree(store)
	require.NoError(t, err)
	expectedRoot := tree.Root()

	_, err = tree.Append(testEntryWire(0))
	require.ErrorIs(t, err, expectedErr)
	require.Equal(t, uint64(0), tree.Size())
	require.Equal(t, expectedRoot, tree.Root())
	_, found := tree.Lookup(testDataHash(0))
	require.False(t, found)
}

func TestOpenTreeRejectsCorruptMemoryStore(t *testing.T) {
	tests := map[string]func(*MemoryStore){
		"root": func(store *MemoryStore) {
			store.snapshot.State.RootHash[0] ^= 0xff
		},
		"missing entry": func(store *MemoryStore) {
			store.snapshot.Entries = store.snapshot.Entries[:len(store.snapshot.Entries)-1]
		},
		"hash index": func(store *MemoryStore) {
			delete(store.snapshot.DataIndex, dataHashKey(testDataHash(0)))
		},
		"frontier": func(store *MemoryStore) {
			store.snapshot.State.Frontier[0][0] ^= 0xff
		},
	}

	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			store := NewMemoryStore()
			tree, err := OpenTree(store)
			require.NoError(t, err)
			_, err = tree.Append(testEntryWire(0))
			require.NoError(t, err)
			corrupt(store)

			_, err = OpenTree(store)
			require.ErrorIs(t, err, ErrStoreCorrupt)
		})
	}
}

func testStoreRestart(
	t *testing.T,
	store Store,
	reopen func() (Store, error),
) {
	_, entries, expectedRoot := populateStore(t, store)
	reopened, err := reopen()
	require.NoError(t, err)
	assertRestoredTree(t, reopened, entries, expectedRoot)
}

func populateStore(t *testing.T, store Store) (*Tree, [][]byte, []byte) {
	t.Helper()
	tree, err := OpenTree(store)
	require.NoError(t, err)
	entries := make([][]byte, 9)
	for i := range entries {
		entry := testEntry(i)
		entry.DataHashes = append(entry.DataHashes, testDataHash(i+100))
		entryWire := mustEncodeLogEntry(entry)
		entries[i] = bytes.Clone(entryWire)
		leafIndex, err := tree.Append(entryWire)
		require.NoError(t, err)
		require.Equal(t, uint64(i), leafIndex)
		entryWire[len(entryWire)-1] ^= 0xff
	}
	expectedRoot := bytes.Clone(tree.Root().RootHash)
	return tree, entries, expectedRoot
}

func assertRestoredTree(t *testing.T, store Store, entries [][]byte, expectedRoot []byte) {
	t.Helper()
	tree, err := OpenTree(store)
	require.NoError(t, err)
	require.Equal(t, uint64(len(entries)), tree.Size())
	require.Equal(t, expectedRoot, tree.Root().RootHash)
	lastIngestTime, ok := tree.LastIngestTime()
	require.True(t, ok)
	require.Equal(t, testEntry(len(entries)-1).IngestTime, lastIngestTime)
	for i := range entries {
		for _, dataHash := range [][]byte{testDataHash(i), testDataHash(i + 100)} {
			leafIndex, found := tree.Lookup(dataHash)
			require.True(t, found)
			require.Equal(t, uint64(i), leafIndex)
			proof, err := tree.InclusionProof(leafIndex)
			require.NoError(t, err)
			require.NoError(t, VerifyInclusion(dataHash, proof, tree.Root()))
		}
	}
}

type failingStore struct {
	Store
	err error
}

func (s *failingStore) Append(StoreAppend) error {
	return s.err
}
