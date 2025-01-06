//go:generate gondn_tlv_gen
package tlv

import enc "github.com/named-data/ndnd/std/encoding"

type Packet struct {
	//+field:struct:Advertisement
	Advertisement *Advertisement `tlv:"0xC9"`
	//+field:struct:PrefixOpList
	PrefixOpList *PrefixOpList `tlv:"0x12D"`
}

type Advertisement struct {
	//+field:sequence:*AdvEntry:struct:AdvEntry
	Entries []*AdvEntry `tlv:"0xCA"`
}

type AdvEntry struct {
	//+field:struct:Destination
	Destination *Destination `tlv:"0xCC"`
	//+field:struct:Destination
	NextHop *Destination `tlv:"0xCE"`
	//+field:natural
	Cost uint64 `tlv:"0xD0"`
	//+field:natural
	OtherCost uint64 `tlv:"0xD2"`
}

type Destination struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
}

type PrefixOpList struct {
	//+field:struct:Destination
	ExitRouter *Destination `tlv:"0xCC"`
	//+field:bool
	PrefixOpReset bool `tlv:"0x12E"`
	//+field:sequence:*PrefixOpAdd:struct:PrefixOpAdd
	PrefixOpAdds []*PrefixOpAdd `tlv:"0x130"`
	//+field:sequence:*PrefixOpRemove:struct:PrefixOpRemove
	PrefixOpRemoves []*PrefixOpRemove `tlv:"0x132"`
}

type PrefixOpAdd struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:natural
	Cost uint64 `tlv:"0xD0"`
}

type PrefixOpRemove struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
}

type Status struct {
	//+field:struct:Destination
	NetworkName *Destination `tlv:"0x191"`
	//+field:struct:Destination
	RouterName *Destination `tlv:"0x193"`
}
