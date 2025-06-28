//go:generate gondn_tlv_gen
package spec_2022

import enc "github.com/named-data/ndnd/std/encoding"

// +tlv-model:nocopy,private
type Packet struct {
	//+field:struct:Interest:nocopy
	Interest *Interest `tlv:"0x05"`
	//+field:struct:Data:nocopy
	Data *Data `tlv:"0x06"`
	//+field:struct:LpPacket:nocopy
	LpPacket *LpPacket `tlv:"0x64"`
}

type NameContainer struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
}
