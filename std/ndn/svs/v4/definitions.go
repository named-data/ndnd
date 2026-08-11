//go:generate gondn_tlv_gen
package svs

import (
	enc "github.com/named-data/ndnd/std/encoding"
)

// FullStateVector is the wire form of a complete State Vector carried in a
// Sync message or published at .../32=sv/<version>. The presence of this
// TLV (rather than PartialStateVector) tells the receiver that the embedded
// StateVector represents the sender's full membership view.
type FullStateVector struct {
	//+field:struct:StateVector
	StateVector *StateVector `tlv:"0xc9"`
}

// PartialStateVector is the wire form of a publication-time subset State
// Vector. The presence of this TLV tells the receiver that omitted entries
// are a sender-selected subset (not a partition or out-of-date sender).
type PartialStateVector struct {
	//+field:struct:StateVector
	StateVector *StateVector `tlv:"0xc9"`
}

// SvsData is a tagged union: the wire carries exactly one of
// FullStateVector, PartialStateVector, or SvsDataRef. The choice of TLV
// type replaces the previous VectorType discriminator. MemberSetHash
// (`mhash`) is present on all three forms and lets receivers detect
// membership mismatches without walking a full StateVector.
type SvsData struct {
	//+field:binary:optional
	MemberSetHash []byte `tlv:"0xcb"`
	//+field:struct:FullStateVector
	FullStateVector *FullStateVector `tlv:"0xcd"`
	//+field:struct:PartialStateVector
	PartialStateVector *PartialStateVector `tlv:"0xce"`
	//+field:name
	SvsDataRef enc.Name `tlv:"0x07"`
}

type StateVector struct {
	//+field:sequence:*StateVectorEntry:struct:StateVectorEntry
	Entries []*StateVectorEntry `tlv:"0xca"`
}

type StateVectorEntry struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:sequence:*SeqNoEntry:struct:SeqNoEntry
	SeqNoEntries []*SeqNoEntry `tlv:"0xd2"`
}

type SeqNoEntry struct {
	//+field:natural
	BootstrapTime uint64 `tlv:"0xd4"`
	//+field:natural
	SeqNo uint64 `tlv:"0xd6"`
}

// MembershipTuple is one (Name, BootstrapTime) pair used to compute MemberSetHash.
type MembershipTuple struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:natural
	BootstrapTime uint64 `tlv:"0xd4"`
}

// +tlv-model:nocopy
type PassiveState struct {
	//+field:sequence:[]byte:binary:[]byte
	Data [][]byte `tlv:"0xfa0"`
}
