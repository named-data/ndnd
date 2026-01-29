package table

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
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

// (AI GENERATED DESCRIPTION): Creates a new `FwData` instance with the specified name, leaving other fields (such as content) unset.
func makeData(name enc.Name) *defn.FwData {
	return &defn.FwData{NameV: name}
}

// (AI GENERATED DESCRIPTION): Creates a new FwInterest packet with the given name and a randomly generated nonce.
func makeInterest(name enc.Name) *defn.FwInterest {
	return &defn.FwInterest{
		NameV:  name,
		NonceV: optional.Some(rand.Uint32()),
	}
}

// (AI GENERATED DESCRIPTION): Sets the replacement policy for the ContentStore to the specified policy string.
func setReplacementPolicy(policy string) {
	core.C.Tables.ContentStore.ReplacementPolicy = policy
}

// (AI GENERATED DESCRIPTION): Test verifies that a newly created PIT-CS instance starts empty and that all search operations (interest or data lookup) correctly return nil when no entries have been added.
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
	data := makeData(name)
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

	data2 := makeData(name)
	pitEntries = pitCS.FindInterestPrefixMatchByDataEnc(data2, nil)
	assert.Equal(t, len(pitEntries), 0)

	csEntry = pitCS.FindMatchingDataFromCS(interest2)
	assert.Nil(t, csEntry)
}

// (AI GENERATED DESCRIPTION): Verifies that a PitCS instance correctly reports whether content‑store admission is enabled by checking that its IsCsAdmitting() method reflects the global CS admission configuration flag.
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

// (AI GENERATED DESCRIPTION): Tests that a newly created PitCS reports the correct CS‑serving state by mirroring the global CfgCsServe configuration.
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

// (AI GENERATED DESCRIPTION): Unit test that verifies PitCS.InsertInterest correctly creates or updates PIT entries, detects duplicate nonces, preserves entry state, and supports prefix relationships between interests.
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

// (AI GENERATED DESCRIPTION): Tests that PitCS.RemoveInterest correctly removes a PIT entry in various scenarios, verifying the PIT size updates appropriately.
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

// (AI GENERATED DESCRIPTION): **FindInterestExactMatchEnc**: Looks up and returns the PIT entry whose name exactly matches the encoded name of the supplied interest, or `nil` if no such entry exists.
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

// (AI GENERATED DESCRIPTION): FindInterestPrefixMatchByDataEnc returns all PIT entries whose interest name is a prefix of the supplied Data packet name, enabling prefix‑based lookup for satisfying pending interests.
func TestFindInterestPrefixMatchByData(t *testing.T) {
	setReplacementPolicy("lru")

	// Basically the same as FindInterestPrefixMatch, but with data instead
	pitCS := NewPitCS(func(PitEntry) {})
	name, _ := enc.NameFromStr("/interest1")
	data := makeData(name)
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
	data2 := makeData(name2)
	pitEntriesEmpty := pitCS.FindInterestPrefixMatchByDataEnc(data2, nil)
	assert.Equal(t, len(pitEntriesEmpty), 0)

	// /a exists but we're looking for /a/b, return just /a
	longername, _ := enc.NameFromStr("/interest1/more_name_content")
	interest3 := makeInterest(longername)
	data3 := makeData(longername)

	pitEntriesEmpty = pitCS.FindInterestPrefixMatchByDataEnc(data3, nil)
	assert.Equal(t, len(pitEntriesEmpty), 1)

	// /a/b exists but we're looking for /a
	// should return both /a/b and /a
	_, _ = pitCS.InsertInterest(interest3, hint, inFace)
	pitEntries = pitCS.FindInterestPrefixMatchByDataEnc(data3, nil)
	assert.Equal(t, len(pitEntries), 2)
}

// (AI GENERATED DESCRIPTION): Inserts or updates an outrecord in a PIT entry, recording the given face and the latest nonce of the supplied interest.
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
	assert.True(t, outRecord.LatestNonce == interest.NonceV.Unwrap())

	// Update existing outrecord
	oldNonce := uint32(2)
	interest.NonceV.Set(oldNonce)
	interest.NonceV.Set(3)
	outRecord = pitEntry.InsertOutRecord(interest, inFace)
	assert.Equal(t, outRecord.Face, inFace)
	assert.True(t, outRecord.LatestNonce == interest.NonceV.Unwrap())
	assert.False(t, outRecord.LatestNonce == oldNonce)

	// Add new outrecord on a different face
	inFace2 := uint64(2222)
	outRecord = pitEntry.InsertOutRecord(interest, inFace2)
	assert.Equal(t, outRecord.Face, inFace2)
	assert.True(t, outRecord.LatestNonce == interest.NonceV.Unwrap())
}

// (AI GENERATED DESCRIPTION): Test verifies that inserting interests into a PIT entry correctly creates, updates, and maintains out‑records per face, ensuring the latest nonce is stored for each face.
func TestGetOutRecords(t *testing.T) {
	setReplacementPolicy("lru")

	getOutRecords := func(pitEntry PitEntry) []*PitOutRecord {
		records := []*PitOutRecord{}
		for _, record := range pitEntry.OutRecords() {
			records = append(records, record)
		}
		return records
	}

	pitCS := NewPitCS(func(PitEntry) {})
	name, _ := enc.NameFromStr("/interest1")
	hint, _ := enc.NameFromStr("/")
	inFace := uint64(1111)
	interest := makeInterest(name)
	interest.CanBePrefixV = true

	// New outrecord
	pitEntry, _ := pitCS.InsertInterest(interest, hint, inFace)
	_ = pitEntry.InsertOutRecord(interest, inFace)
	outRecords := getOutRecords(pitEntry)
	assert.Equal(t, len(outRecords), 1)
	assert.Equal(t, outRecords[0].Face, inFace)
	assert.True(t, outRecords[0].LatestNonce == interest.NonceV.Unwrap())

	// Update existing outrecord
	oldNonce := uint32(2)
	interest.NonceV.Set(oldNonce)
	interest.NonceV.Set(3)
	_ = pitEntry.InsertOutRecord(interest, inFace)
	outRecords = getOutRecords(pitEntry)
	assert.Equal(t, len(outRecords), 1)
	assert.Equal(t, outRecords[0].Face, inFace)
	assert.True(t, outRecords[0].LatestNonce == interest.NonceV.Unwrap())

	// Add new outrecord on a different face
	inFace2 := uint64(2222)
	_ = pitEntry.InsertOutRecord(interest, inFace2)
	outRecords = getOutRecords(pitEntry)
	sort.Slice(outRecords, func(i, j int) bool {
		// Sort by face ID
		return outRecords[i].Face < outRecords[j].Face
	})
	assert.Equal(t, len(outRecords), 2)

	assert.Equal(t, outRecords[0].Face, inFace)
	assert.True(t, outRecords[0].LatestNonce == interest.NonceV.Unwrap())

	assert.Equal(t, outRecords[1].Face, inFace2)
	assert.True(t, outRecords[1].LatestNonce == interest.NonceV.Unwrap())
}

// (AI GENERATED DESCRIPTION): Tests that the PIT-CS component can retrieve the correct Data packet from the CS cache based on an Interest (exact or prefix match), correctly update existing entries, avoid duplicate insertions, and evict entries when the CS capacity is exceeded.
func FindMatchingDataFromCS(t *testing.T) {
	setReplacementPolicy("lru")
	CfgSetCsCapacity(1024)

	pitCS := NewPitCS(func(PitEntry) {})

	// Data does not already exist
	name1, _ := enc.NameFromStr("/ndn/edu/ucla/ping/123")
	interest1 := makeInterest(name1)
	interest1.CanBePrefixV = false

	pkt, _ := defn.ParseFwPacket(enc.NewBufferView(VALID_DATA_1), false)
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

	pkt, _ = defn.ParseFwPacket(enc.NewBufferView(VALID_DATA_2), false)
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
