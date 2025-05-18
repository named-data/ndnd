//go:generate gondn_tlv_gen
package tlv

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

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
	//+field:string
	Version string `tlv:"0x191"`
	//+field:struct:Destination
	NetworkName *Destination `tlv:"0x193"`
	//+field:struct:Destination
	RouterName *Destination `tlv:"0x195"`
	//+field:natural
	NRibEntries uint64 `tlv:"0x197"`
	//+field:natural
	NNeighbors uint64 `tlv:"0x199"`
	//+field:natural
	NFibEntries uint64 `tlv:"0x19B"`
}

type PrefixInjection struct {
	//+field:sequence:[]byte:binary:[]byte
	StapledCertificates [][]byte `tlv:"0x216"`
	//+field:binary
	ObjectWire []byte `tlv:"0x06"`
}

type PrefixInjectionInnerContent struct {
	//+field:natural
	ExpirationPeriod uint64 `tlv:"0x6d"`
	//+field:struct:spec_2022.ValidityPeriod
	ValidityPeriod *spec_2022.ValidityPeriod `tlv:"0xfd"`
	//+field:natural:optional
	Cost optional.Optional[uint64] `tlv:"0x6a"`
}
