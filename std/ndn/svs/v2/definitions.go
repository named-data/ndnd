//go:generate gondn_tlv_gen
package sync

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
	//+field:natural
	SeqNo uint64 `tlv:"0xcc"`
}
