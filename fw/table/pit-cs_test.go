package table

import (
	"bytes"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/stretchr/testify/assert"
)

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
	bpe.SetExpirationTime(newTime)
	assert.Equal(t, bpe.ExpirationTime(), newTime)

	bpe.SetSatisfied(false)
	assert.Equal(t, bpe.Satisfied(), false)
}

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

func TestInsertInRecord(t *testing.T) {
	// Case 1: interest does not already exist in basePitEntry.inRecords
	name, _ := enc.NameFromStr("/something")
	val := new(uint32)
	*val = 1
	interest := &spec.Interest{
		NameV:  name,
		NonceV: val,
	}
	pitToken := []byte("abc")
	bpe := basePitEntry{
		inRecords: make(map[uint64]*PitInRecord),
	}
	faceID := uint64(1234)
	inRecord, alreadyExists, _ := bpe.InsertInRecord(interest, faceID, pitToken)
	assert.False(t, alreadyExists)
	assert.Equal(t, inRecord.Face, faceID)
	assert.Equal(t, inRecord.LatestNonce == *interest.Nonce(), true)
	assert.Equal(t, inRecord.LatestInterest, interest.Name())
	assert.Equal(t, bytes.Compare(inRecord.PitToken, pitToken), 0)
	assert.Equal(t, len(bpe.InRecords()), 1)

	record, ok := bpe.InRecords()[faceID]
	assert.True(t, ok)
	assert.Equal(t, record, inRecord)

	// Case 2: interest already exists in basePitEntry.inRecords
	*interest.NonceV = 2 // get a "new" interest by resetting its nonce
	inRecord, alreadyExists, prevNonce := bpe.InsertInRecord(interest, faceID, pitToken)
	assert.True(t, alreadyExists)
	assert.Equal(t, prevNonce, uint64(1))
	assert.Equal(t, inRecord.Face, faceID)
	assert.Equal(t, inRecord.LatestNonce == *interest.Nonce(), true)
	assert.Equal(t, inRecord.LatestInterest, interest.Name())
	assert.Equal(t, bytes.Compare(inRecord.PitToken, pitToken), 0)
	assert.Equal(t, len(bpe.InRecords()), 1) // should update the original record in place
	record, ok = bpe.InRecords()[faceID]
	assert.True(t, ok)
	assert.Equal(t, record, inRecord)

	// Add another inRecord
	name2, _ := enc.NameFromStr("/another_something")
	val2 := new(uint32)
	*val2 = 1
	interest2 := &spec.Interest{
		NameV:  name2,
		NonceV: val,
	}
	pitToken2 := []byte("xyz")
	faceID2 := uint64(6789)
	inRecord, alreadyExists, _ = bpe.InsertInRecord(interest2, faceID2, pitToken2)
	assert.False(t, alreadyExists)
	assert.Equal(t, inRecord.Face, faceID2)
	assert.Equal(t, inRecord.LatestNonce == *interest2.Nonce(), true)
	assert.Equal(t, inRecord.LatestInterest, interest2.Name())
	assert.Equal(t, bytes.Compare(inRecord.PitToken, pitToken2), 0)
	assert.Equal(t, len(bpe.InRecords()), 2) // should be a new inRecord
	record, ok = bpe.InRecords()[faceID2]
	assert.True(t, ok)
	assert.Equal(t, record, inRecord)

	// TODO: For unit testing the timestamps and expiration times, the time
	// module needs to be mocked so that we can control the return value
	// of time.Now()
}

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

	csData, csWire, _ := bpe.Copy()
	assert.Equal(t, csData.Name(), name)
	assert.Equal(t, csWire, VALID_DATA_1)
}
