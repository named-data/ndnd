//go:generate gondn_tlv_gen
package svs

import (
	enc "github.com/named-data/ndnd/std/encoding"
)

type SvsData struct {
	//+field:struct:StateVector
	StateVector *StateVector `tlv:"0xc9"`
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

// +tlv-model:nocopy
type PassiveState struct {
	//+field:sequence:[]byte:binary:[]byte
	Data [][]byte `tlv:"0xfa0"`
}
