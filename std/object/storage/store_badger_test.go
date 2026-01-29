//go:build !js

package storage_test

import (
	"os"
	"testing"

	"github.com/named-data/ndnd/std/object/storage"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Runs a suite of tests that create a BadgerStore, verify its basic CRUD, range removal, and transactional behavior, and then close the store.
func TestBadgerStore(t *testing.T) {
	tu.SetT(t)
	dir := "badger-test"
	os.RemoveAll(dir)
	defer os.RemoveAll(dir)

	store, err := storage.NewBadgerStore(dir)
	require.NoError(t, err)
	testStoreBasic(t, store)
	testStoreRemoveRange(t, store)
	testStoreTxn(t, store)
	require.NoError(t, store.Close())
}
