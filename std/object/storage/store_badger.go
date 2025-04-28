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

func NewBadgerStore(path string) (*BadgerStore, error) {
	db, err := badger.Open(badger.DefaultOptions(path))
	if err != nil {
		return nil, err
	}

	return &BadgerStore{db: db}, nil
}

func (s *BadgerStore) Close() error {
	return s.db.Close()
}

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

func (s *BadgerStore) Put(name enc.Name, wire []byte) error {
	key := s.nameKey(name)
	return s.update(func(txn *badger.Txn) error {
		return txn.Set(key, wire)
	})
}

func (s *BadgerStore) Remove(name enc.Name) error {
	key := s.nameKey(name)
	return s.update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

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

func (s *BadgerStore) Begin() (ndn.Store, error) {
	if s.tx != nil {
		panic("Begin() called within a write transaction")
	}
	tx := s.db.NewTransaction(true)
	return &BadgerStore{db: s.db, tx: tx}, nil
}

func (s *BadgerStore) Commit() error {
	if s.tx == nil {
		panic("Commit() called without a write transaction")
	}
	return s.tx.Commit()
}

func (s *BadgerStore) Rollback() error {
	if s.tx == nil {
		panic("Rollback() called without a write transaction")
	}
	s.tx.Discard()
	return nil
}

func (s *BadgerStore) nameKey(name enc.Name) []byte {
	return name.BytesInner()
}

func (s *BadgerStore) update(f func(tx *badger.Txn) error) error {
	if s.tx != nil {
		return f(s.tx)
	} else {
		return s.db.Update(f)
	}
}
