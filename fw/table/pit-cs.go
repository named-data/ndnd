/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

// PitCsTable dictates what functionality a Pit-Cs table should implement
// Warning: All functions must be called in the same forwarding goroutine as the creation of the table.
type PitCsTable interface {
	InsertInterest(interest ndn.Interest, hint enc.Name, inFace uint64) (PitEntry, bool)
	RemoveInterest(pitEntry PitEntry) bool
	FindInterestExactMatchEnc(interest ndn.Interest) PitEntry
	FindInterestPrefixMatchByDataEnc(data ndn.Data, token *uint32) []PitEntry
	PitSize() int

	InsertData(data ndn.Data, wire []byte)
	FindMatchingDataFromCS(interest ndn.Interest) CsEntry
	CsSize() int
	IsCsAdmitting() bool
	IsCsServing() bool

	eraseCsDataFromReplacementStrategy(index uint64)
	updatePitExpiry(pitEntry PitEntry)

	// UpdateTimer returns the channel used to signal regular Update() calls in the forwarding thread.
	// <- UpdateTimer() and Update() must be called in pairs.
	UpdateTimer() <-chan struct{}
	// Update() does whatever the PIT table needs to do regularly.
	// It may schedule the next UpdateTimer().
	Update()
}

// PitEntry dictates what entries in a PIT-CS table should implement
type PitEntry interface {
	PitCs() PitCsTable
	EncName() enc.Name
	CanBePrefix() bool
	MustBeFresh() bool
	ForwardingHintNew() enc.Name
	// Interests must match in terms of Forwarding Hint to be aggregated in PIT.
	InRecords() map[uint64]*PitInRecord   // Key is face ID
	OutRecords() map[uint64]*PitOutRecord // Key is face ID
	ExpirationTime() time.Time
	SetExpirationTime(t time.Time)
	Satisfied() bool
	SetSatisfied(isSatisfied bool)

	Token() uint32

	InsertInRecord(interest ndn.Interest, face uint64, incomingPitToken []byte) (*PitInRecord, bool, uint64)
	InsertOutRecord(interest ndn.Interest, face uint64) *PitOutRecord

	GetOutRecords() []*PitOutRecord
	ClearOutRecords()
	ClearInRecords()
}

// basePitEntry contains PIT entry properties common to all tables.
type basePitEntry struct {
	// lowercase fields so that they aren't exported
	encname           enc.Name
	canBePrefix       bool
	mustBeFresh       bool
	forwardingHintNew enc.Name
	// Interests must match in terms of Forwarding Hint to be
	// aggregated in PIT.
	inRecords      map[uint64]*PitInRecord  // Key is face ID
	outRecords     map[uint64]*PitOutRecord // Key is face ID
	expirationTime time.Time
	satisfied      bool

	token uint32
}

// PitInRecord records an incoming Interest on a given face.
type PitInRecord struct {
	Face            uint64
	LatestTimestamp time.Time
	LatestNonce     uint64
	ExpirationTime  time.Time
	PitToken        []byte
}

// PitOutRecord records an outgoing Interest on a given face.
type PitOutRecord struct {
	Face            uint64
	LatestTimestamp time.Time
	LatestNonce     uint64
	ExpirationTime  time.Time
}

// CsEntry is an entry in a thread's CS.
type CsEntry interface {
	Index() uint64 // the hash of the entry, for fast lookup
	StaleTime() time.Time
	Copy() (ndn.Data, []byte, error)
}

type baseCsEntry struct {
	index     uint64
	staleTime time.Time
	wire      []byte
}

// InsertInRecord finds or inserts an InRecord for the face, updating the
// metadata and returning whether there was already an in-record in the entry.
// The third return value is the previous nonce if the in-record already existed.
func (bpe *basePitEntry) InsertInRecord(
	interest ndn.Interest,
	face uint64,
	incomingPitToken []byte,
) (*PitInRecord, bool, uint64) {
	lifetime := time.Millisecond * 4000
	if interest.Lifetime() != nil {
		lifetime = *interest.Lifetime()
	}

	var record *PitInRecord
	var ok bool
	if record, ok = bpe.inRecords[face]; !ok {
		record := new(PitInRecord)
		record.Face = face
		record.LatestNonce = *interest.Nonce()
		record.LatestTimestamp = time.Now()
		record.ExpirationTime = time.Now().Add(lifetime)
		record.PitToken = append([]byte{}, incomingPitToken...)
		bpe.inRecords[face] = record
		return record, false, 0
	}

	// Existing record
	previousNonce := record.LatestNonce
	record.LatestNonce = *interest.Nonce()
	record.LatestTimestamp = time.Now()
	record.ExpirationTime = time.Now().Add(lifetime)
	return record, true, previousNonce
}

// SetExpirationTimerToNow updates the expiration timer to the current time.
func SetExpirationTimerToNow(e PitEntry) {
	e.SetExpirationTime(time.Now())
	e.PitCs().updatePitExpiry(e)
}

// UpdateExpirationTimer updates the expiration timer to the latest expiration
// time of any in or out record in the entry.
func UpdateExpirationTimer(e PitEntry) {
	e.SetExpirationTime(time.Now())

	for _, record := range e.InRecords() {
		if record.ExpirationTime.After(e.ExpirationTime()) {
			e.SetExpirationTime(record.ExpirationTime)
		}
	}

	for _, record := range e.OutRecords() {
		if record.ExpirationTime.After(e.ExpirationTime()) {
			e.SetExpirationTime(record.ExpirationTime)
		}
	}

	e.PitCs().updatePitExpiry(e)
}

// /// Setters and Getters /////
func (bpe *basePitEntry) EncName() enc.Name {
	return bpe.encname
}

func (bpe *basePitEntry) CanBePrefix() bool {
	return bpe.canBePrefix
}

func (bpe *basePitEntry) MustBeFresh() bool {
	return bpe.mustBeFresh
}
func (bpe *basePitEntry) ForwardingHintNew() enc.Name {
	return bpe.forwardingHintNew
}

func (bpe *basePitEntry) InRecords() map[uint64]*PitInRecord {
	return bpe.inRecords
}

func (bpe *basePitEntry) OutRecords() map[uint64]*PitOutRecord {
	return bpe.outRecords
}

// ClearInRecords removes all in-records from the PIT entry.
func (bpe *basePitEntry) ClearInRecords() {
	bpe.inRecords = make(map[uint64]*PitInRecord)
}

// ClearOutRecords removes all out-records from the PIT entry.
func (bpe *basePitEntry) ClearOutRecords() {
	bpe.outRecords = make(map[uint64]*PitOutRecord)
}

func (bpe *basePitEntry) ExpirationTime() time.Time {
	return bpe.expirationTime
}

func (bpe *basePitEntry) SetExpirationTime(t time.Time) {
	bpe.expirationTime = t
}

func (bpe *basePitEntry) Satisfied() bool {
	return bpe.satisfied
}

func (bpe *basePitEntry) SetSatisfied(isSatisfied bool) {
	bpe.satisfied = isSatisfied
}

func (bpe *basePitEntry) Token() uint32 {
	return bpe.token
}

func (bce *baseCsEntry) Index() uint64 {
	return bce.index
}

func (bce *baseCsEntry) StaleTime() time.Time {
	return bce.staleTime
}

func (bce *baseCsEntry) Copy() (ndn.Data, []byte, error) {
	wire := make([]byte, len(bce.wire))
	copy(wire, bce.wire)

	data, _, err := spec.ReadPacket(enc.NewBufferReader(wire))
	if err != nil {
		return nil, nil, err
	}

	return data.Data, wire, nil
}
