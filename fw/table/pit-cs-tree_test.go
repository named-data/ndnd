package table

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/named-data/ndnd/fw/core"
	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/utils"
	"github.com/stretchr/testify/assert"
)

var VALID_DATA_1 = []byte{
	0x06, 0x4c, 0x07, 0x1b, 0x08, 0x03, 0x6e, 0x64, 0x6e, 0x08, 0x03, 0x65,
	0x64, 0x75, 0x08, 0x04, 0x75, 0x63, 0x6c, 0x61, 0x08, 0x04, 0x70, 0x69,
	0x6e, 0x67, 0x08, 0x03, 0x31, 0x32, 0x33, 0x14, 0x04, 0x19, 0x02, 0x03,
	0xe8, 0x15, 0x00, 0x16, 0x03, 0x1b, 0x01, 0x00, 0x17, 0x20, 0x8e, 0x94,
	0xbd, 0xc8, 0xea, 0x4d, 0x7d, 0xba, 0x4a, 0x51, 0x1a, 0x7e, 0xe4, 0x16,
	0xd4, 0x8f, 0x4d, 0x78, 0x17, 0xca, 0x0e, 0x51, 0xe8, 0x64, 0x05, 0x27,
	0x01, 0x5b, 0xf7, 0x96, 0xb7, 0x60,
}

var VALID_DATA_2 = []byte{
	0x06, 0x4f, 0x07, 0x1e, 0x08, 0x03, 0x6e, 0x64, 0x6e, 0x08, 0x03, 0x65,
	0x64, 0x75, 0x08, 0x07, 0x61, 0x72, 0x69, 0x7a, 0x6f, 0x6e, 0x61, 0x08,
	0x04, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x03, 0x31, 0x32, 0x34, 0x14, 0x04,
	0x19, 0x02, 0x03, 0xe8, 0x15, 0x00, 0x16, 0x03, 0x1b, 0x01, 0x00, 0x17,
	0x20, 0xc9, 0x9d, 0x60, 0x1a, 0xc3, 0x2a, 0x76, 0xb0, 0x4a, 0x34, 0x80,
	0xba, 0x14, 0x01, 0x67, 0x17, 0x21, 0x50, 0x80, 0x10, 0xfc, 0x6c, 0x47,
	0x7d, 0xa9, 0x20, 0xea, 0x8b, 0xda, 0xf6, 0x13, 0xed,
}

func makeData(name enc.Name, content enc.Wire) *spec.Data {
	return &spec.Data{
		NameV:    name,
		ContentV: content,
	}
}

func makeInterest(name enc.Name) *spec.Interest {
	return &spec.Interest{
		NameV:  name,
		NonceV: utils.IdPtr(rand.Uint32()),
	}
}

func setReplacementPolicy(policy string) {
	core.C.Tables.ContentStore.ReplacementPolicy = policy
}

func TestNewPitCSTree(t *testing.T) {
	setReplacementPolicy("lru")
	pitCS := NewPitCS(func(PitEntry) {})

	// Initialization size should be 0
	assert.Equal(t, pitCS.PitSize(), 0)
	assert.Equal(t, pitCS.CsSize(), 0)

	// Any search should return nil
	// Interest is some random string
	name, _ := enc.NameFromStr("/interest1")
	interest := makeInterest(name)
	pitEntry := pitCS.FindInterestExactMatchEnc(interest)
	assert.Nil(t, pitEntry)
	data := makeData(name, enc.Wire{})
	pitEntries := pitCS.FindInterestPrefixMatchByDataEnc(data, nil)
	assert.Equal(t, len(pitEntries), 0)

	// Test searching CS
	csEntry := pitCS.FindMatchingDataFromCS(interest)
	assert.Nil(t, csEntry)

	// Interest is root - still should not match
	name, _ = enc.NameFromStr("/")
	interest2 := makeInterest(name)
	pitEntry = pitCS.FindInterestExactMatchEnc(interest2)
	assert.Nil(t, pitEntry)

	data2 := makeData(name, enc.Wire{})
	pitEntries = pitCS.FindInterestPrefixMatchByDataEnc(data2, nil)
	assert.Equal(t, len(pitEntries), 0)

	csEntry = pitCS.FindMatchingDataFromCS(interest2)
	assert.Nil(t, csEntry)
}

func TestIsCsAdmitting(t *testing.T) {
	setReplacementPolicy("lru")
	CfgSetCsAdmit(false)

	pitCS := NewPitCS(func(PitEntry) {})
	assert.Equal(t, pitCS.IsCsAdmitting(), false)
	assert.Equal(t, CfgCsAdmit(), false)

	CfgSetCsAdmit(true)
	pitCS = NewPitCS(func(PitEntry) {})
	assert.Equal(t, pitCS.IsCsAdmitting(), true)
	assert.Equal(t, CfgCsAdmit(), true)
}

func TestIsCsServing(t *testing.T) {
	setReplacementPolicy("lru")
	CfgSetCsServe(false)

	pitCS := NewPitCS(func(PitEntry) {})
	assert.Equal(t, pitCS.IsCsServing(), false)
	assert.Equal(t, CfgCsServe(), false)

	CfgSetCsServe(true)
	pitCS = NewPitCS(func(PitEntry) {})
	assert.Equal(t, pitCS.IsCsServing(), true)
	assert.Equal(t, CfgCsServe(), true)
}

func TestInsertInterest(t *testing.T) {
	setReplacementPolicy("lru")

	// Interest does not already exist
	hint, _ := enc.NameFromStr("/")
	inFace := uint64(1111)
	name, _ := enc.NameFromStr("/interest1")
	interest := makeInterest(name)

	pitCS := NewPitCS(func(PitEntry) {})

	pitEntry, duplicateNonce := pitCS.InsertInterest(interest, hint, inFace)

	assert.False(t, duplicateNonce)

	assert.True(t, pitEntry.EncName().Equal(name))
	assert.Equal(t, pitEntry.CanBePrefix(), interest.CanBePrefixV)
	assert.Equal(t, pitEntry.MustBeFresh(), interest.MustBeFreshV)
	assert.True(t, pitEntry.ForwardingHintNew().Equal(hint))
	assert.False(t, pitEntry.Satisfied())

	assert.Equal(t, len(pitEntry.InRecords()), 0)
	assert.Equal(t, len(pitEntry.OutRecords()), 0)
	assert.Equal(t, pitEntry.PitCs(), pitCS)
	// expiration time should be cancelled upon receiving a new interest
	assert.Equal(t, pitEntry.ExpirationTime(), time.Unix(0, 0))

	assert.Equal(t, pitCS.PitSize(), 1)

	// Interest already exists, so we should just update it
	// insert the interest again, the same data should be returned
	pitEntry, duplicateNonce = pitCS.InsertInterest(interest, hint, inFace)

	assert.False(t, duplicateNonce)

	assert.True(t, pitEntry.EncName().Equal(name))
	assert.Equal(t, pitEntry.CanBePrefix(), interest.CanBePrefixV)
	assert.Equal(t, pitEntry.MustBeFresh(), interest.MustBeFreshV)
	assert.True(t, pitEntry.ForwardingHintNew().Equal(hint))
	assert.False(t, pitEntry.Satisfied())

	assert.Equal(t, len(pitEntry.InRecords()), 0)
	assert.Equal(t, len(pitEntry.OutRecords()), 0)
	assert.Equal(t, pitEntry.PitCs(), pitCS)
	// expiration time should be cancelled upon receiving a new interest
	assert.Equal(t, pitEntry.ExpirationTime(), time.Unix(0, 0))

	assert.Equal(t, pitCS.PitSize(), 1)

	// Looping interest, duplicate nonce
	pitEntry.InsertInRecord(interest, inFace, []byte("abc"))
	inFace2 := uint64(2222)
	pitEntry, duplicateNonce = pitCS.InsertInterest(interest, hint, inFace2)

	assert.True(t, duplicateNonce)
	assert.True(t, pitEntry.EncName().Equal(name))
	assert.Equal(t, pitEntry.CanBePrefix(), interest.CanBePrefixV)
	assert.Equal(t, pitEntry.MustBeFresh(), interest.MustBeFreshV)
	assert.True(t, pitEntry.ForwardingHintNew().Equal(hint))
	assert.False(t, pitEntry.Satisfied())

	assert.Equal(t, len(pitEntry.InRecords()), 1)
	assert.Equal(t, len(pitEntry.OutRecords()), 0)
	assert.Equal(t, pitEntry.PitCs(), pitCS)
	// expiration time should be cancelled upon receiving a new interest
	assert.Equal(t, pitEntry.ExpirationTime(), time.Unix(0, 0))

	assert.Equal(t, pitCS.PitSize(), 1)

	// Insert another distinct interest to check it works
	hint2, _ := enc.NameFromStr("/")
	inFace3 := uint64(3333)
	name2, _ := enc.NameFromStr("/interest2")
	interest2 := makeInterest(name2)
	pitEntry, duplicateNonce = pitCS.InsertInterest(interest2, hint2, inFace3)

	assert.False(t, duplicateNonce)
	assert.True(t, pitEntry.EncName().Equal(name2))
	assert.Equal(t, pitEntry.CanBePrefix(), interest2.CanBePrefixV)
	assert.Equal(t, pitEntry.MustBeFresh(), interest2.MustBeFreshV)
	assert.True(t, pitEntry.ForwardingHintNew().Equal(hint2))
	assert.False(t, pitEntry.Satisfied())

	assert.Equal(t, len(pitEntry.InRecords()), 0)
	assert.Equal(t, len(pitEntry.OutRecords()), 0)
	assert.Equal(t, pitEntry.PitCs(), pitCS)
	// expiration time should be cancelled upon receiving a new interest
	assert.Equal(t, pitEntry.ExpirationTime(), time.Unix(0, 0))

	assert.Equal(t, pitCS.PitSize(), 2)

	// PitCS with 2 interests, prefixes of each other.
	pitCS = NewPitCS(func(PitEntry) {})

	hint, _ = enc.NameFromStr("/")
	inFace = uint64(4444)
	name, _ = enc.NameFromStr("/interest")
	interest = makeInterest(name)

	name2, _ = enc.NameFromStr("/interest/longer")
	interest2 = makeInterest(name2)
	pitEntry, duplicateNonce = pitCS.InsertInterest(interest, hint, inFace)
	pitEntry2, duplicateNonce2 := pitCS.InsertInterest(interest2, hint, inFace)

	assert.False(t, duplicateNonce)
	// assert.True(t, pitEntry.Name().Equals(name))
	// assert.Equal(t, pitEntry.CanBePrefix(), interest.CanBePrefix())
	// assert.Equal(t, pitEntry.MustBeFresh(), interest.MustBeFresh())
	// assert.True(t, pitEntry.ForwardingHint().Equals(hint))
	assert.True(t, pitEntry.EncName().Equal(name))
	assert.Equal(t, pitEntry.CanBePrefix(), interest.CanBePrefixV)
	assert.Equal(t, pitEntry.MustBeFresh(), interest.MustBeFreshV)
	assert.True(t, pitEntry.ForwardingHintNew().Equal(hint))
	assert.False(t, pitEntry.Satisfied())

	assert.Equal(t, len(pitEntry.InRecords()), 0)
	assert.Equal(t, len(pitEntry.OutRecords()), 0)
	assert.Equal(t, pitEntry.PitCs(), pitCS)
	// expiration time should be cancelled upon receiving a new interest
	assert.Equal(t, pitEntry.ExpirationTime(), time.Unix(0, 0))

	assert.False(t, duplicateNonce2)
	// assert.True(t, pitEntry2.Name().Equals(name2))
	// assert.Equal(t, pitEntry2.CanBePrefix(), interest2.CanBePrefix())
	// assert.Equal(t, pitEntry2.MustBeFresh(), interest2.MustBeFresh())
	// assert.True(t, pitEntry2.ForwardingHint().Equals(hint))
	assert.True(t, pitEntry2.EncName().Equal(name2))
	assert.Equal(t, pitEntry2.CanBePrefix(), interest2.CanBePrefixV)
	assert.Equal(t, pitEntry2.MustBeFresh(), interest2.MustBeFreshV)
	assert.True(t, pitEntry2.ForwardingHintNew().Equal(hint2))
	assert.False(t, pitEntry2.Satisfied())

	assert.Equal(t, len(pitEntry2.InRecords()), 0)
	assert.Equal(t, len(pitEntry2.OutRecords()), 0)
	assert.Equal(t, pitEntry2.PitCs(), pitCS)
	// expiration time should be cancelled upon receiving a new interest
	assert.Equal(t, pitEntry2.ExpirationTime(), time.Unix(0, 0))

	assert.Equal(t, pitCS.PitSize(), 2)
}

func TestRemoveInterest(t *testing.T) {
	setReplacementPolicy("lru")

	pitCS := NewPitCS(func(PitEntry) {})
	hint, _ := enc.NameFromStr("/")
	inFace := uint64(1111)
	name1, _ := enc.NameFromStr("/interest1")
	interest1 := makeInterest(name1)

	// Simple insert and removal
	pitEntry, _ := pitCS.InsertInterest(interest1, hint, inFace)
	removedInterest := pitCS.RemoveInterest(pitEntry)
	assert.True(t, removedInterest)
	assert.Equal(t, pitCS.PitSize(), 0)

	// Remove a new pit entry
	name2, _ := enc.NameFromStr("/interest2")
	interest2 := makeInterest(name2)
	pitEntry2, _ := pitCS.InsertInterest(interest2, hint, inFace)
	assert.Equal(t, pitCS.PitSize(), 1)

	removedInterest = pitCS.RemoveInterest(pitEntry2)
	assert.True(t, removedInterest)
	assert.Equal(t, pitCS.PitSize(), 0)

	// Remove a pit entry from a node with more than 1 pit entry
	hint2, _ := enc.NameFromStr("/2")
	hint3, _ := enc.NameFromStr("/3")
	hint4, _ := enc.NameFromStr("/4")
	_, _ = pitCS.InsertInterest(interest2, hint, inFace)
	_, _ = pitCS.InsertInterest(interest2, hint2, inFace)
	pitEntry3, _ := pitCS.InsertInterest(interest2, hint3, inFace)
	_, _ = pitCS.InsertInterest(interest2, hint4, inFace)

	removedInterest = pitCS.RemoveInterest(pitEntry3)
	assert.True(t, removedInterest)
	assert.Equal(t, pitCS.PitSize(), 3)

	// Remove PIT entry from a node with more than 1 child
	pitCS = NewPitCS(func(PitEntry) {})
	name1, _ = enc.NameFromStr("/root/1")
	name2, _ = enc.NameFromStr("/root/2")
	name3, _ := enc.NameFromStr("/root/3")
	interest1 = makeInterest(name1)
	interest2 = makeInterest(name2)
	interest3 := makeInterest(name3)

	_, _ = pitCS.InsertInterest(interest1, hint, inFace)
	pitEntry2, _ = pitCS.InsertInterest(interest2, hint, inFace)
	_, _ = pitCS.InsertInterest(interest3, hint3, inFace)

	removedInterest = pitCS.RemoveInterest(pitEntry2)
	assert.True(t, removedInterest)
	assert.Equal(t, pitCS.PitSize(), 2)
}

func TestFindInterestExactMatch(t *testing.T) {
	setReplacementPolicy("lru")

	pitCS := NewPitCS(func(PitEntry) {})
	hint, _ := enc.NameFromStr("/")
	inFace := uint64(1111)
	name, _ := enc.NameFromStr("/interest1")
	interest := makeInterest(name)

	// Simple insert and find
	_, _ = pitCS.InsertInterest(interest, hint, inFace)

	pitEntry := pitCS.FindInterestExactMatchEnc(interest)
	assert.NotNil(t, pitEntry)
	assert.True(t, pitEntry.EncName().Equal(name))
	assert.Equal(t, pitEntry.CanBePrefix(), interest.CanBePrefixV)
	assert.Equal(t, pitEntry.MustBeFresh(), interest.MustBeFreshV)
	assert.True(t, pitEntry.ForwardingHintNew().Equal(hint))
	assert.Equal(t, len(pitEntry.InRecords()), 0)
	assert.Equal(t, len(pitEntry.OutRecords()), 0)
	assert.False(t, pitEntry.Satisfied())

	// Look for nonexistent name
	name2, _ := enc.NameFromStr("/nonexistent")
	interest2 := makeInterest(name2)
	pitEntryNil := pitCS.FindInterestExactMatchEnc(interest2)
	assert.Nil(t, pitEntryNil)

	// /a exists but we're looking for /a/b
	longername, _ := enc.NameFromStr("/interest1/more_name_content")
	interest3 := makeInterest(longername)

	pitEntryNil = pitCS.FindInterestExactMatchEnc(interest3)
	assert.Nil(t, pitEntryNil)

	// /a/b exists but we're looking for /a only
	pitCS.RemoveInterest(pitEntry)
	_, _ = pitCS.InsertInterest(interest3, hint, inFace)
	pitEntryNil = pitCS.FindInterestExactMatchEnc(interest)
	assert.Nil(t, pitEntryNil)
}

func TestFindInterestPrefixMatchByData(t *testing.T) {
	setReplacementPolicy("lru")

	// Basically the same as FindInterestPrefixMatch, but with data instead
	pitCS := NewPitCS(func(PitEntry) {})
	name, _ := enc.NameFromStr("/interest1")
	data := makeData(name, enc.Wire{})
	hint, _ := enc.NameFromStr("/")
	inFace := uint64(1111)
	interest := makeInterest(name)
	interest.CanBePrefixV = true

	// Simple insert and find
	_, _ = pitCS.InsertInterest(interest, hint, inFace)

	pitEntries := pitCS.FindInterestPrefixMatchByDataEnc(data, nil)
	assert.Equal(t, len(pitEntries), 1)
	assert.True(t, pitEntries[0].EncName().Equal(interest.NameV))
	assert.Equal(t, pitEntries[0].CanBePrefix(), interest.CanBePrefixV)
	assert.Equal(t, pitEntries[0].MustBeFresh(), interest.MustBeFreshV)
	assert.True(t, pitEntries[0].ForwardingHintNew().Equal(hint))
	assert.Equal(t, len(pitEntries[0].InRecords()), 0)
	assert.Equal(t, len(pitEntries[0].OutRecords()), 0)
	assert.False(t, pitEntries[0].Satisfied())

	// Look for nonexistent name
	name2, _ := enc.NameFromStr("/nonexistent")
	data2 := makeData(name2, enc.Wire{})
	pitEntriesEmpty := pitCS.FindInterestPrefixMatchByDataEnc(data2, nil)
	assert.Equal(t, len(pitEntriesEmpty), 0)

	// /a exists but we're looking for /a/b, return just /a
	longername, _ := enc.NameFromStr("/interest1/more_name_content")
	interest3 := makeInterest(longername)
	data3 := makeData(longername, enc.Wire{})

	pitEntriesEmpty = pitCS.FindInterestPrefixMatchByDataEnc(data3, nil)
	assert.Equal(t, len(pitEntriesEmpty), 1)

	// /a/b exists but we're looking for /a
	// should return both /a/b and /a
	_, _ = pitCS.InsertInterest(interest3, hint, inFace)
	pitEntries = pitCS.FindInterestPrefixMatchByDataEnc(data3, nil)
	assert.Equal(t, len(pitEntries), 2)
}

func TestInsertOutRecord(t *testing.T) {
	setReplacementPolicy("lru")

	pitCS := NewPitCS(func(PitEntry) {})
	name, _ := enc.NameFromStr("/interest1")
	hint, _ := enc.NameFromStr("/")
	inFace := uint64(1111)
	interest := makeInterest(name)
	interest.CanBePrefixV = true

	// New outrecord
	pitEntry, _ := pitCS.InsertInterest(interest, hint, inFace)
	outRecord := pitEntry.InsertOutRecord(interest, inFace)
	assert.Equal(t, outRecord.Face, inFace)
	assert.True(t, outRecord.LatestNonce == *interest.Nonce())

	// Update existing outrecord
	oldNonce := new(uint64)
	*oldNonce = 2
	*interest.NonceV = uint32(*oldNonce)
	*interest.NonceV = 3
	outRecord = pitEntry.InsertOutRecord(interest, inFace)
	assert.Equal(t, outRecord.Face, inFace)
	assert.True(t, outRecord.LatestNonce == *interest.Nonce())
	assert.False(t, outRecord.LatestNonce == *oldNonce)

	// Add new outrecord on a different face
	inFace2 := uint64(2222)
	outRecord = pitEntry.InsertOutRecord(interest, inFace2)
	assert.Equal(t, outRecord.Face, inFace2)
	assert.True(t, outRecord.LatestNonce == *interest.Nonce())
}

func TestGetOutRecords(t *testing.T) {
	setReplacementPolicy("lru")

	pitCS := NewPitCS(func(PitEntry) {})
	name, _ := enc.NameFromStr("/interest1")
	hint, _ := enc.NameFromStr("/")
	inFace := uint64(1111)
	interest := makeInterest(name)
	interest.CanBePrefixV = true

	// New outrecord
	pitEntry, _ := pitCS.InsertInterest(interest, hint, inFace)
	_ = pitEntry.InsertOutRecord(interest, inFace)
	outRecords := pitEntry.GetOutRecords()
	assert.Equal(t, len(outRecords), 1)
	assert.Equal(t, outRecords[0].Face, inFace)
	assert.True(t, outRecords[0].LatestNonce == *interest.Nonce())

	// Update existing outrecord
	oldNonce := new(uint32)
	*oldNonce = 2
	*interest.NonceV = *oldNonce
	*interest.NonceV = 3
	_ = pitEntry.InsertOutRecord(interest, inFace)
	outRecords = pitEntry.GetOutRecords()
	assert.Equal(t, len(outRecords), 1)
	assert.Equal(t, outRecords[0].Face, inFace)
	assert.True(t, outRecords[0].LatestNonce == *interest.Nonce())

	// Add new outrecord on a different face
	inFace2 := uint64(2222)
	_ = pitEntry.InsertOutRecord(interest, inFace2)
	outRecords = pitEntry.GetOutRecords()
	sort.Slice(outRecords, func(i, j int) bool {
		// Sort by face ID
		return outRecords[i].Face < outRecords[j].Face
	})
	assert.Equal(t, len(outRecords), 2)

	assert.Equal(t, outRecords[0].Face, inFace)
	assert.True(t, outRecords[0].LatestNonce == *interest.Nonce())

	assert.Equal(t, outRecords[1].Face, inFace2)
	assert.True(t, outRecords[1].LatestNonce == *interest.Nonce())
}

func FindMatchingDataFromCS(t *testing.T) {
	setReplacementPolicy("lru")
	CfgSetCsCapacity(1024)

	pitCS := NewPitCS(func(PitEntry) {})

	// Data does not already exist
	name1, _ := enc.NameFromStr("/ndn/edu/ucla/ping/123")
	interest1 := makeInterest(name1)
	interest1.CanBePrefixV = false

	pkt, _, _ := spec.ReadPacket(enc.NewBufferReader(VALID_DATA_1))
	data1 := pkt.Data

	pitCS.InsertData(data1, VALID_DATA_1)
	csEntry1 := pitCS.FindMatchingDataFromCS(interest1)
	_, csWire, _ := csEntry1.Copy()
	assert.Equal(t, pitCS.CsSize(), 1)
	assert.True(t, bytes.Equal(csWire, VALID_DATA_1))

	// Insert data associated with same name, so we should just update it
	// Should not result in a new CsEntry
	pitCS.InsertData(data1, VALID_DATA_1)
	csEntry1 = pitCS.FindMatchingDataFromCS(interest1)
	_, csWire, _ = csEntry1.Copy()
	assert.Equal(t, pitCS.CsSize(), 1)
	assert.True(t, bytes.Equal(csWire, VALID_DATA_1))

	// Insert some different data, should result in creation of new CsEntry
	name2, _ := enc.NameFromStr("/ndn/edu/arizona/ping/124")
	interest2 := makeInterest(name2)
	interest2.CanBePrefixV = false

	pkt, _, _ = spec.ReadPacket(enc.NewBufferReader(VALID_DATA_2))
	data2 := pkt.Data

	pitCS.InsertData(data2, VALID_DATA_2)

	csEntry2 := pitCS.FindMatchingDataFromCS(interest2)
	_, csWire, _ = csEntry2.Copy()
	assert.Equal(t, pitCS.CsSize(), 2)
	assert.True(t, bytes.Equal(csWire, VALID_DATA_2))

	// Check CanBePrefix flag
	name3, _ := enc.NameFromStr("/ndn/edu/ucla")
	interest3 := makeInterest(name3)
	interest3.CanBePrefixV = true

	csEntry3 := pitCS.FindMatchingDataFromCS(interest3)
	_, csWire, _ = csEntry3.Copy()
	assert.True(t, bytes.Equal(csWire, VALID_DATA_1))

	// Reduced CS capacity to check that eviction occurs
	CfgSetCsCapacity(1)
	pitCS = NewPitCS(func(PitEntry) {})
	pitCS.InsertData(data1, VALID_DATA_1)
	pitCS.InsertData(data2, VALID_DATA_2)
	assert.Equal(t, pitCS.CsSize(), 1)
}
