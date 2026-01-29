//go:build !js

package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// Store implementation using badger
type BadgerStore struct {
	db *badger.DB
	tx *badger.Txn
}

// (AI GENERATED DESCRIPTION): Initializes a new BadgerStore by opening a Badger database at the specified path and returns the store or an error.
func NewBadgerStore(path string) (*BadgerStore, error) {
	db, err := badger.Open(badger.DefaultOptions(path))
	if err != nil {
		return nil, err
	}

	return &BadgerStore{db: db}, nil
}

// (AI GENERATED DESCRIPTION): Closes the underlying Badger database of the store and returns any error.
func (s *BadgerStore) Close() error {
	return s.db.Close()
}

// (AI GENERATED DESCRIPTION): Retrieves a value from the Badger store by name, optionally returning the most recent entry that matches a given prefix, and panics if called while a write transaction is active.
func (s *BadgerStore) Get(name enc.Name, prefix bool) (wire []byte, err error) {
	if s.tx != nil {
		panic("Get() called within a write transaction")
	}

	key := s.nameKey(name)
	err = s.db.View(func(txn *badger.Txn) error {
		// Exact match
		if !prefix {
			item, err := txn.Get(key)
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			wire, err = item.ValueCopy(nil)
			return err
		}

		// Prefix match
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true // newest first
		it := txn.NewIterator(opts)
		defer it.Close()

		it.Seek(append(key, 0xFF))
		if !it.ValidForPrefix(key) {
			return nil
		}

		item := it.Item()
		wire, err = item.ValueCopy(nil)
		return err
	})

	return
}

// (AI GENERATED DESCRIPTION): Stores the supplied packet wire bytes under the key derived from the given name in the Badger database.
func (s *BadgerStore) Put(name enc.Name, wire []byte) error {
	key := s.nameKey(name)
	return s.update(func(txn *badger.Txn) error {
		return txn.Set(key, wire)
	})
}

// (AI GENERATED DESCRIPTION): Deletes the record associated with the specified name from the BadgerStore.
func (s *BadgerStore) Remove(name enc.Name) error {
	key := s.nameKey(name)
	return s.update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// (AI GENERATED DESCRIPTION): Deletes all store entries whose keys begin with the given name prefix.
func (s *BadgerStore) RemovePrefix(prefix enc.Name) error {
	keyPfx := s.nameKey(prefix)

	return s.update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // keys only
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(keyPfx); it.ValidForPrefix(keyPfx); it.Next() {
			key := it.Item().KeyCopy(nil)
			if err := txn.Delete(key); err != nil {
				return err
			}
		}

		return nil
	})
}

// (AI GENERATED DESCRIPTION): Deletes all key‑value pairs in the Badger store whose keys fall within the flat name range between the specified first and last components for the given prefix.
func (s *BadgerStore) RemoveFlatRange(prefix enc.Name, first enc.Component, last enc.Component) error {
	firstKey := s.nameKey(prefix.Append(first))
	lastKey := s.nameKey(prefix.Append(last))
	if bytes.Compare(firstKey, lastKey) > 0 {
		return fmt.Errorf("firstKey > lastKey")
	}

	return s.update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // keys only
		it := txn.NewIterator(opts)
		defer it.Close()

		it.Seek(firstKey)
		for {
			if !it.Valid() {
				return nil
			}

			key := it.Item().KeyCopy(nil)
			if bytes.Compare(key, lastKey) > 0 {
				return nil
			}

			if err := txn.Delete(key); err != nil {
				return err
			}
			it.Next()
		}
	})
}

// (AI GENERATED DESCRIPTION): Starts a new write transaction on the BadgerStore and returns a store instance tied to that transaction, panicking if a transaction is already active.
func (s *BadgerStore) Begin() (ndn.Store, error) {
	if s.tx != nil {
		panic("Begin() called within a write transaction")
	}
	tx := s.db.NewTransaction(true)
	return &BadgerStore{db: s.db, tx: tx}, nil
}

// (AI GENERATED DESCRIPTION): Commits the current BadgerDB transaction, writing all pending changes to the database and panicking if called when no write transaction is active.
func (s *BadgerStore) Commit() error {
	if s.tx == nil {
		panic("Commit() called without a write transaction")
	}
	return s.tx.Commit()
}

// (AI GENERATED DESCRIPTION): Reverts any uncommitted changes in the current transaction by discarding it.
func (s *BadgerStore) Rollback() error {
	if s.tx == nil {
		panic("Rollback() called without a write transaction")
	}
	s.tx.Discard()
	return nil
}

// (AI GENERATED DESCRIPTION): Returns the inner byte slice of the supplied `enc.Name` to be used as a key in the Badger store.
func (s *BadgerStore) nameKey(name enc.Name) []byte {
	return name.BytesInner()
}

// (AI GENERATED DESCRIPTION): Executes the supplied update function within the Badger store, using an existing transaction if one is active or starting a new transaction otherwise.
func (s *BadgerStore) update(f func(tx *badger.Txn) error) error {
	if s.tx != nil {
		return f(s.tx)
	} else {
		return s.db.Update(f)
	}
}
