package merklelog

import (
	"bytes"
	"fmt"
	"sync"
)

// MemoryStore is an in-memory Store implementation for tests and ephemeral logs.
type MemoryStore struct {
	mutex    sync.Mutex
	snapshot *StoreSnapshot
}

// NewMemoryStore creates an empty in-memory log store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		snapshot: &StoreSnapshot{
			State:     emptyStoreState(),
			DataIndex: make(map[[HashSize]byte]uint64),
		},
	}
}

// Load returns a consistent copy of all stored state.
func (s *MemoryStore) Load() (*StoreSnapshot, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return cloneStoreSnapshot(s.snapshot), nil
}

// Append atomically stores one entry, its hash index, and the resulting state.
func (s *MemoryStore) Append(update StoreAppend) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	nextState, err := validateStoreAppend(s.snapshot.State, update)
	if err != nil {
		return err
	}
	entry, _, err := decodeLogEntry(update.EntryWire)
	if err != nil {
		return err
	}
	seen := make(map[[HashSize]byte]struct{}, len(entry.DataHashes))
	for _, dataHash := range entry.DataHashes {
		key := dataHashKey(dataHash)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate within entry", ErrDuplicateDataHash)
		}
		if leafIndex, ok := s.snapshot.DataIndex[key]; ok {
			return fmt.Errorf("%w at leaf %d", ErrDuplicateDataHash, leafIndex)
		}
		seen[key] = struct{}{}
	}

	leafIndex := update.ExpectedSize
	s.snapshot.Entries = append(s.snapshot.Entries, bytes.Clone(update.EntryWire))
	for key := range seen {
		s.snapshot.DataIndex[key] = leafIndex
	}
	s.snapshot.State = cloneStoreState(*nextState)
	return nil
}
