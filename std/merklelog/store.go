package merklelog

import (
	"bytes"
	"fmt"
	"math/bits"
	"time"
)

// StoreState is the durable Merkle state after a complete append.
type StoreState struct {
	TreeSize       uint64
	RootHash       []byte
	Frontier       [][]byte
	LastIngestTime time.Duration
}

// StoreSnapshot is one consistent view of the complete persisted log.
type StoreSnapshot struct {
	State     StoreState
	Entries   [][]byte
	DataIndex map[[HashSize]byte]uint64
}

// StoreAppend describes one atomic transition from ExpectedSize to State.
type StoreAppend struct {
	ExpectedSize uint64
	EntryWire    []byte
	State        StoreState
}

// Store persists raw log entries, their Data hash index, and derived tree state
// in one atomic append operation.
type Store interface {
	Load() (*StoreSnapshot, error)
	Append(update StoreAppend) error
}

func emptyStoreState() StoreState {
	return StoreState{RootHash: rootFromFrontier(nil)}
}

func validateStoreState(state StoreState) error {
	if len(state.RootHash) != HashSize {
		return fmt.Errorf("root hash length is %d, want %d", len(state.RootHash), HashSize)
	}
	if state.LastIngestTime < 0 || state.LastIngestTime%time.Millisecond != 0 {
		return fmt.Errorf("last ingestion time is invalid")
	}
	expectedLevels := bits.Len64(state.TreeSize)
	if len(state.Frontier) != expectedLevels {
		return fmt.Errorf(
			"frontier has %d levels, want %d for tree size %d",
			len(state.Frontier),
			expectedLevels,
			state.TreeSize,
		)
	}
	for level, subtreeHash := range state.Frontier {
		occupied := state.TreeSize&(uint64(1)<<level) != 0
		if occupied && len(subtreeHash) != HashSize {
			return fmt.Errorf("frontier level %d hash length is %d, want %d", level, len(subtreeHash), HashSize)
		}
		if !occupied && subtreeHash != nil {
			return fmt.Errorf("frontier level %d should be empty", level)
		}
	}
	if !bytes.Equal(rootFromFrontier(state.Frontier), state.RootHash) {
		return fmt.Errorf("frontier does not produce stored root")
	}
	if state.TreeSize == 0 && state.LastIngestTime != 0 {
		return fmt.Errorf("empty tree has a last ingestion time")
	}
	return nil
}

func validateStoreAppend(current StoreState, update StoreAppend) (*StoreState, error) {
	if err := validateStoreState(current); err != nil {
		return nil, fmt.Errorf("%w: current state: %v", ErrStoreCorrupt, err)
	}
	if update.ExpectedSize != current.TreeSize {
		return nil, fmt.Errorf(
			"%w: expected size %d, current size %d",
			ErrStoreStateChanged,
			update.ExpectedSize,
			current.TreeSize,
		)
	}
	if current.TreeSize == ^uint64(0) {
		return nil, fmt.Errorf("tree size overflow")
	}
	entry, _, err := decodeLogEntry(update.EntryWire)
	if err != nil {
		return nil, err
	}
	if current.TreeSize > 0 && entry.IngestTime <= current.LastIngestTime {
		return nil, fmt.Errorf("ingestion time does not increase")
	}

	nextFrontier := appendFrontier(current.Frontier, hashLeaf(update.EntryWire))
	expected := StoreState{
		TreeSize:       current.TreeSize + 1,
		RootHash:       rootFromFrontier(nextFrontier),
		Frontier:       nextFrontier,
		LastIngestTime: entry.IngestTime,
	}
	if !equalStoreState(expected, update.State) {
		return nil, fmt.Errorf("append state does not match entry and current frontier")
	}
	return &expected, nil
}

func cloneStoreState(state StoreState) StoreState {
	return StoreState{
		TreeSize:       state.TreeSize,
		RootHash:       bytes.Clone(state.RootHash),
		Frontier:       cloneHashes(state.Frontier),
		LastIngestTime: state.LastIngestTime,
	}
}

func equalStoreState(left StoreState, right StoreState) bool {
	if left.TreeSize != right.TreeSize ||
		left.LastIngestTime != right.LastIngestTime ||
		!bytes.Equal(left.RootHash, right.RootHash) ||
		len(left.Frontier) != len(right.Frontier) {
		return false
	}
	for level := range left.Frontier {
		if !bytes.Equal(left.Frontier[level], right.Frontier[level]) {
			return false
		}
	}
	return true
}

func cloneStoreSnapshot(snapshot *StoreSnapshot) *StoreSnapshot {
	ret := &StoreSnapshot{
		State:     cloneStoreState(snapshot.State),
		Entries:   make([][]byte, len(snapshot.Entries)),
		DataIndex: make(map[[HashSize]byte]uint64, len(snapshot.DataIndex)),
	}
	for i, entryWire := range snapshot.Entries {
		ret.Entries[i] = bytes.Clone(entryWire)
	}
	for dataHash, leafIndex := range snapshot.DataIndex {
		ret.DataIndex[dataHash] = leafIndex
	}
	return ret
}
