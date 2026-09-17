//go:build !js

package merklelog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/dgraph-io/badger/v4"
)

var (
	storeStateKey    = []byte{0x00}
	storeEntryKeyPfx = []byte{0x01}
	storeHashKeyPfx  = []byte{0x02}
)

const (
	storeStateMagic   = "MLOG"
	storeStateVersion = byte(1)
	storeStateHeader  = 4 + 1 + 8 + 8 + HashSize + 1
)

// BadgerStore persists the Merkle log in a dedicated Badger database.
type BadgerStore struct {
	db *badger.DB
}

// NewBadgerStore opens or creates a persistent Merkle log store at path.
func NewBadgerStore(path string) (*BadgerStore, error) {
	options := badger.DefaultOptions(path).WithSyncWrites(true)
	db, err := badger.Open(options)
	if err != nil {
		return nil, err
	}
	return &BadgerStore{db: db}, nil
}

// Close closes the underlying Badger database.
func (s *BadgerStore) Close() error {
	return s.db.Close()
}

// Load returns one transactionally consistent snapshot of the persisted log.
func (s *BadgerStore) Load() (snapshot *StoreSnapshot, err error) {
	snapshot = &StoreSnapshot{
		State:     emptyStoreState(),
		DataIndex: make(map[[HashSize]byte]uint64),
	}
	err = s.db.View(func(txn *badger.Txn) error {
		state, found, err := loadBadgerState(txn)
		if err != nil {
			return err
		}
		if !found {
			hasEntries := badgerHasPrefix(txn, storeEntryKeyPfx)
			hasIndex := badgerHasPrefix(txn, storeHashKeyPfx)
			if hasEntries || hasIndex {
				return fmt.Errorf("%w: records exist without tree state", ErrStoreCorrupt)
			}
			return nil
		}
		snapshot.State = state
		snapshot.Entries = nil
		expectedIndex := uint64(0)
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(storeEntryKeyPfx); it.ValidForPrefix(storeEntryKeyPfx); it.Next() {
			key := it.Item().Key()
			if len(key) != 1+8 {
				return fmt.Errorf("%w: malformed entry key", ErrStoreCorrupt)
			}
			leafIndex := binary.BigEndian.Uint64(key[1:])
			if leafIndex != expectedIndex {
				return fmt.Errorf("%w: found entry %d, expected %d", ErrStoreCorrupt, leafIndex, expectedIndex)
			}
			entryWire, err := it.Item().ValueCopy(nil)
			if err != nil {
				return err
			}
			snapshot.Entries = append(snapshot.Entries, entryWire)
			expectedIndex++
		}
		if expectedIndex != state.TreeSize {
			return fmt.Errorf("%w: found %d entries for tree size %d", ErrStoreCorrupt, expectedIndex, state.TreeSize)
		}

		for it.Seek(storeHashKeyPfx); it.ValidForPrefix(storeHashKeyPfx); it.Next() {
			key := it.Item().Key()
			if len(key) != 1+HashSize {
				return fmt.Errorf("%w: malformed Data hash index key", ErrStoreCorrupt)
			}
			value, err := it.Item().ValueCopy(nil)
			if err != nil {
				return err
			}
			if len(value) != 8 {
				return fmt.Errorf("%w: malformed Data hash index value", ErrStoreCorrupt)
			}
			leafIndex := binary.BigEndian.Uint64(value)
			if leafIndex >= state.TreeSize {
				return fmt.Errorf("%w: indexed leaf %d is outside tree", ErrStoreCorrupt, leafIndex)
			}
			var dataHash [HashSize]byte
			copy(dataHash[:], key[1:])
			snapshot.DataIndex[dataHash] = leafIndex
		}
		return nil
	})
	return snapshot, err
}

// Append writes one complete tree transition in a Badger transaction.
func (s *BadgerStore) Append(update StoreAppend) error {
	return s.db.Update(func(txn *badger.Txn) error {
		current, found, err := loadBadgerState(txn)
		if err != nil {
			return err
		}
		if !found {
			current = emptyStoreState()
			if badgerHasPrefix(txn, storeEntryKeyPfx) || badgerHasPrefix(txn, storeHashKeyPfx) {
				return fmt.Errorf("%w: records exist without tree state", ErrStoreCorrupt)
			}
		}
		nextState, err := validateStoreAppend(current, update)
		if err != nil {
			return err
		}
		entry, _, err := decodeLogEntry(update.EntryWire)
		if err != nil {
			return err
		}

		entryKey := badgerEntryKey(update.ExpectedSize)
		if _, err := txn.Get(entryKey); err == nil {
			return fmt.Errorf("%w: entry %d already exists", ErrStoreCorrupt, update.ExpectedSize)
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		seen := make(map[[HashSize]byte]struct{}, len(entry.DataHashes))
		for _, dataHash := range entry.DataHashes {
			key := dataHashKey(dataHash)
			if _, ok := seen[key]; ok {
				return fmt.Errorf("%w: duplicate within entry", ErrDuplicateDataHash)
			}
			seen[key] = struct{}{}
			hashKey := badgerHashKey(key)
			if item, err := txn.Get(hashKey); err == nil {
				value, copyErr := item.ValueCopy(nil)
				if copyErr != nil {
					return copyErr
				}
				if len(value) != 8 {
					return fmt.Errorf("%w: malformed Data hash index value", ErrStoreCorrupt)
				}
				return fmt.Errorf(
					"%w at leaf %d",
					ErrDuplicateDataHash,
					binary.BigEndian.Uint64(value),
				)
			} else if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
		}

		if err := txn.Set(entryKey, update.EntryWire); err != nil {
			return err
		}
		indexValue := make([]byte, 8)
		binary.BigEndian.PutUint64(indexValue, update.ExpectedSize)
		for key := range seen {
			if err := txn.Set(badgerHashKey(key), indexValue); err != nil {
				return err
			}
		}
		stateValue, err := encodeStoreState(*nextState)
		if err != nil {
			return err
		}
		return txn.Set(storeStateKey, stateValue)
	})
}

func loadBadgerState(txn *badger.Txn) (StoreState, bool, error) {
	item, err := txn.Get(storeStateKey)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return StoreState{}, false, nil
	}
	if err != nil {
		return StoreState{}, false, err
	}
	value, err := item.ValueCopy(nil)
	if err != nil {
		return StoreState{}, false, err
	}
	state, err := decodeStoreState(value)
	if err != nil {
		return StoreState{}, false, fmt.Errorf("%w: %v", ErrStoreCorrupt, err)
	}
	return state, true, nil
}

func encodeStoreState(state StoreState) ([]byte, error) {
	if err := validateStoreState(state); err != nil {
		return nil, err
	}
	if len(state.Frontier) > 64 {
		return nil, fmt.Errorf("frontier has too many levels")
	}
	size := storeStateHeader
	for _, subtreeHash := range state.Frontier {
		size++
		if subtreeHash != nil {
			size += HashSize
		}
	}
	ret := make([]byte, size)
	copy(ret, storeStateMagic)
	ret[4] = storeStateVersion
	binary.BigEndian.PutUint64(ret[5:13], state.TreeSize)
	binary.BigEndian.PutUint64(ret[13:21], uint64(state.LastIngestTime/time.Millisecond))
	copy(ret[21:21+HashSize], state.RootHash)
	ret[21+HashSize] = byte(len(state.Frontier))
	pos := storeStateHeader
	for _, subtreeHash := range state.Frontier {
		if subtreeHash == nil {
			ret[pos] = 0
			pos++
			continue
		}
		ret[pos] = 1
		pos++
		copy(ret[pos:], subtreeHash)
		pos += HashSize
	}
	return ret, nil
}

func decodeStoreState(value []byte) (StoreState, error) {
	if len(value) < storeStateHeader {
		return StoreState{}, fmt.Errorf("state is too short")
	}
	if !bytes.Equal(value[:4], []byte(storeStateMagic)) || value[4] != storeStateVersion {
		return StoreState{}, fmt.Errorf("unsupported state format")
	}
	lastMillis := binary.BigEndian.Uint64(value[13:21])
	if lastMillis > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return StoreState{}, fmt.Errorf("last ingestion time overflows time.Duration")
	}
	state := StoreState{
		TreeSize:       binary.BigEndian.Uint64(value[5:13]),
		LastIngestTime: time.Duration(lastMillis) * time.Millisecond,
		RootHash:       bytes.Clone(value[21 : 21+HashSize]),
	}
	frontierCount := int(value[21+HashSize])
	state.Frontier = make([][]byte, frontierCount)
	pos := storeStateHeader
	for level := range state.Frontier {
		if pos >= len(value) {
			return StoreState{}, fmt.Errorf("frontier level %d is missing", level)
		}
		present := value[pos]
		pos++
		switch present {
		case 0:
		case 1:
			if pos+HashSize > len(value) {
				return StoreState{}, fmt.Errorf("frontier level %d hash is truncated", level)
			}
			state.Frontier[level] = bytes.Clone(value[pos : pos+HashSize])
			pos += HashSize
		default:
			return StoreState{}, fmt.Errorf("frontier level %d has invalid presence marker", level)
		}
	}
	if pos != len(value) {
		return StoreState{}, fmt.Errorf("state has %d trailing bytes", len(value)-pos)
	}
	if err := validateStoreState(state); err != nil {
		return StoreState{}, err
	}
	return state, nil
}

func badgerEntryKey(leafIndex uint64) []byte {
	key := make([]byte, 1+8)
	key[0] = storeEntryKeyPfx[0]
	binary.BigEndian.PutUint64(key[1:], leafIndex)
	return key
}

func badgerHashKey(dataHash [HashSize]byte) []byte {
	key := make([]byte, 1+HashSize)
	key[0] = storeHashKeyPfx[0]
	copy(key[1:], dataHash[:])
	return key
}

func badgerHasPrefix(txn *badger.Txn, prefix []byte) bool {
	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = false
	it := txn.NewIterator(opts)
	defer it.Close()
	it.Seek(prefix)
	return it.ValidForPrefix(prefix)
}
