//go:generate gondn_tlv_gen
package gen_composition

import (
	enc "github.com/named-data/ndnd/std/encoding"
)

type _IntArray struct {
	//+field:sequence:uint64:natural
	Words []uint64 `tlv:"0x01"`
}

type _NameArray struct {
	//+field:sequence:enc.Name:name
	Names []enc.Name `tlv:"0x07"`
}

type _Inner struct {
	//+field:natural
	Num uint64 `tlv:"0x01"`
}

type _Nested struct {
	//+field:struct:Inner
	Val _Inner `tlv:"0x02"`
}

type _NestedSeq struct {
	//+field:sequence:*Inner:struct:Inner
	Vals []*_Inner `tlv:"0x03"`
}

// +tlv-model:nocopy,private
type _InnerWire1 struct {
	//+field:wire
	Wire1 enc.Wire `tlv:"0x01"`
	//+field:natural:optional
	Num *uint64 `tlv:"0x02"`
}

// +tlv-model:nocopy,private
type _InnerWire2 struct {
	//+field:wire
	Wire2 enc.Wire `tlv:"0x03"`
}

// +tlv-model:nocopy
type _NestedWire struct {
	//+field:struct:InnerWire1:nocopy
	W1 *_InnerWire1 `tlv:"0x04"`
	//+field:natural
	N uint64 `tlv:"0x05"`
	//+field:struct:InnerWire2:nocopy
	W2 *_InnerWire2 `tlv:"0x06"`
}
