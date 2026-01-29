package table

import (
	"bytes"
	"testing"
	"time"

	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/assert"
)

// (AI GENERATED DESCRIPTION): Tests that a `basePitEntry` correctly returns its stored name, flags, forwarding hint, expiration time, satisfaction status, token, and that its in‑ and out‑record slices are initially empty.
func TestBasePitEntryGetters(t *testing.T) {
	name, _ := enc.NameFromStr("/something")
	currTime := time.Now()
	bpe := basePitEntry{
		encname:           name,
		canBePrefix:       true,
		mustBeFresh:       true,
		forwardingHintNew: name,
		expirationTime:    currTime,
		satisfied:         true,
		token:             1234,
	}

	assert.True(t, bpe.EncName().Equal(name))
	assert.Equal(t, bpe.CanBePrefix(), true)
	assert.Equal(t, bpe.MustBeFresh(), true)
	assert.True(t, bpe.ForwardingHintNew().Equal(name))
	assert.Equal(t, len(bpe.InRecords()), 0)
	assert.Equal(t, len(bpe.OutRecords()), 0)
	assert.Equal(t, bpe.ExpirationTime(), currTime)
	assert.Equal(t, bpe.Satisfied(), true)
	assert.Equal(t, bpe.Token(), uint32(1234))
}

// (AI GENERATED DESCRIPTION): Verifies that the `basePitEntry` setters correctly update its expiration time and satisfied flag.
func TestBasePitEntrySetters(t *testing.T) {
	name, _ := enc.NameFromStr("/something")
	currTime := time.Now()
	bpe := basePitEntry{
		encname:           name,
		canBePrefix:       true,
		mustBeFresh:       true,
		forwardingHintNew: name,
		expirationTime:    currTime,
		satisfied:         true,
		token:             1234,
	}

	newTime := time.Now()
	bpe.setExpirationTime(newTime)
	assert.Equal(t, bpe.ExpirationTime(), newTime)

	bpe.SetSatisfied(false)
	assert.Equal(t, bpe.Satisfied(), false)
}

// (AI GENERATED DESCRIPTION): Tests that the `ClearInRecords` method removes all entries from the `inRecords` map of a `basePitEntry`.
func TestClearInRecords(t *testing.T) {
	inrecord1 := PitInRecord{}
	inrecord2 := PitInRecord{}
	inRecords := map[uint64]*PitInRecord{
		1: &inrecord1,
		2: &inrecord2,
	}
	bpe := basePitEntry{
		inRecords: inRecords,
	}
	assert.NotEqual(t, len(bpe.InRecords()), 0)
	bpe.ClearInRecords()
	assert.Equal(t, len(bpe.InRecords()), 0)
}

// (AI GENERATED DESCRIPTION): Tests that calling ClearOutRecords on a basePitEntry removes all entries from its outRecords map.
func TestClearOutRecords(t *testing.T) {
	outrecord1 := PitOutRecord{}
	outrecord2 := PitOutRecord{}
	outRecords := map[uint64]*PitOutRecord{
		1: &outrecord1,
		2: &outrecord2,
	}
	bpe := basePitEntry{
		outRecords: outRecords,
	}
	assert.NotEqual(t, len(bpe.OutRecords()), 0)
	bpe.ClearOutRecords()
	assert.Equal(t, len(bpe.OutRecords()), 0)
}

// (AI GENERATED DESCRIPTION): InsertInRecord adds or updates an incoming PIT record for the specified face ID with the provided interest nonce and PIT token, returning the record, a flag indicating whether the record was already present, and the previous nonce if it was updated.
func TestInsertInRecord(t *testing.T) {
	// Case 1: interest does not already exist in basePitEntry.inRecords
	name, _ := enc.NameFromStr("/something")
	val := uint32(1)
	interest := &defn.FwInterest{
		NameV:  name,
		NonceV: optional.Some(val),
	}
	pitToken := []byte("abc")
	bpe := basePitEntry{
		inRecords: make(map[uint64]*PitInRecord),
	}
	faceID := uint64(1234)
	inRecord, alreadyExists, _ := bpe.InsertInRecord(interest, faceID, pitToken)
	assert.False(t, alreadyExists)
	assert.Equal(t, inRecord.Face, faceID)
	assert.Equal(t, inRecord.LatestNonce == interest.NonceV.Unwrap(), true)
	assert.Equal(t, bytes.Compare(inRecord.PitToken, pitToken), 0)
	assert.Equal(t, len(bpe.InRecords()), 1)

	record, ok := bpe.InRecords()[faceID]
	assert.True(t, ok)
	assert.Equal(t, record, inRecord)

	// Case 2: interest already exists in basePitEntry.inRecords
	interest.NonceV.Set(2) // get a "new" interest by resetting its nonce
	inRecord, alreadyExists, prevNonce := bpe.InsertInRecord(interest, faceID, pitToken)
	assert.True(t, alreadyExists)
	assert.Equal(t, prevNonce, uint32(1))
	assert.Equal(t, inRecord.Face, faceID)
	assert.Equal(t, inRecord.LatestNonce == interest.NonceV.Unwrap(), true)
	assert.Equal(t, bytes.Compare(inRecord.PitToken, pitToken), 0)
	assert.Equal(t, len(bpe.InRecords()), 1) // should update the original record in place
	record, ok = bpe.InRecords()[faceID]
	assert.True(t, ok)
	assert.Equal(t, record, inRecord)

	// Add another inRecord
	name2, _ := enc.NameFromStr("/another_something")
	val2 := uint32(1)
	interest2 := &defn.FwInterest{
		NameV:  name2,
		NonceV: optional.Some(val2),
	}
	pitToken2 := []byte("xyz")
	faceID2 := uint64(6789)
	inRecord, alreadyExists, _ = bpe.InsertInRecord(interest2, faceID2, pitToken2)
	assert.False(t, alreadyExists)
	assert.Equal(t, inRecord.Face, faceID2)
	assert.Equal(t, inRecord.LatestNonce == interest2.NonceV.Unwrap(), true)
	assert.Equal(t, bytes.Compare(inRecord.PitToken, pitToken2), 0)
	assert.Equal(t, len(bpe.InRecords()), 2) // should be a new inRecord
	record, ok = bpe.InRecords()[faceID2]
	assert.True(t, ok)
	assert.Equal(t, record, inRecord)

	// TODO: For unit testing the timestamps and expiration times, the time
	// module needs to be mocked so that we can control the return value
	// of time.Now()
}

// (AI GENERATED DESCRIPTION): Tests that a baseCsEntry correctly exposes its index and stale time, and that its Copy method returns an identical Data packet (with the expected name) and wire representation without error.
func TestBaseCsEntryGetters(t *testing.T) {
	name, _ := enc.NameFromStr("/ndn/edu/ucla/ping/123")
	currTime := time.Now()
	bpe := baseCsEntry{
		index:     1234,
		staleTime: currTime,
		wire:      VALID_DATA_1,
	}

	assert.Equal(t, bpe.Index(), uint64(1234))
	assert.Equal(t, bpe.StaleTime(), currTime)

	csData, csWire, err := bpe.Copy()
	assert.Nil(t, err)
	assert.Equal(t, csData.NameV, name)
	assert.Equal(t, csWire, VALID_DATA_1)
}
