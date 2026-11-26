package table

import (
	"testing"
	"time"

	"github.com/named-data/ndnd/fw/core"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/stretchr/testify/assert"
)

// (AI GENERATED DESCRIPTION): Tests that Dead Nonce List entries are found after insertion, survive one rotation, and are removed after two rotations.
func TestDeadNonceList(t *testing.T) {
	prev := core.C.Tables.DeadNonceList.Lifetime
	core.C.Tables.DeadNonceList.Lifetime = 20 // ms
	defer func() { core.C.Tables.DeadNonceList.Lifetime = prev }()

	d := NewDeadNonceList()
	defer d.Ticker.Stop()

	name1, _ := enc.NameFromStr("/a/b")
	name2, _ := enc.NameFromStr("/a/c")

	assert.False(t, d.Find(name1, 1))
	assert.False(t, d.Insert(name1, 1))
	assert.True(t, d.Insert(name1, 1))
	assert.True(t, d.Find(name1, 1))
	assert.False(t, d.Find(name1, 2))
	assert.False(t, d.Find(name2, 1))

	// Not rotated before a lifetime has passed
	d.RemoveExpiredEntries()
	assert.True(t, d.Find(name1, 1))

	// Survives the first rotation
	time.Sleep(25 * time.Millisecond)
	d.RemoveExpiredEntries()
	assert.True(t, d.Find(name1, 1))
	assert.False(t, d.Insert(name2, 1))

	// Dropped after the second rotation; name2 was inserted after the first
	time.Sleep(25 * time.Millisecond)
	d.RemoveExpiredEntries()
	assert.False(t, d.Find(name1, 1))
	assert.True(t, d.Find(name2, 1))
	assert.Equal(t, 1, d.Len())

	time.Sleep(25 * time.Millisecond)
	d.RemoveExpiredEntries()
	assert.False(t, d.Find(name2, 1))
	assert.Equal(t, 0, d.Len())
}

// (AI GENERATED DESCRIPTION): Tests that the Dead Nonce List does not keep expired entries regardless of the insertion rate.
func TestDeadNonceListExpiresAll(t *testing.T) {
	prev := core.C.Tables.DeadNonceList.Lifetime
	core.C.Tables.DeadNonceList.Lifetime = 1 // ms
	defer func() { core.C.Tables.DeadNonceList.Lifetime = prev }()

	d := NewDeadNonceList()
	defer d.Ticker.Stop()

	name, _ := enc.NameFromStr("/a")
	for i := range 5000 {
		d.Insert(name, uint32(i))
	}
	for range 2 {
		time.Sleep(2 * time.Millisecond)
		d.RemoveExpiredEntries()
	}
	assert.Equal(t, 0, d.Len())
}
