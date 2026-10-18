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
	EgressRouter *Destination `tlv:"0xCC"`
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
	//+field:bool
	Multicast bool `tlv:"0xD0"`
	//+field:struct:spec_2022.ValidityPeriod
	ValidityPeriod *spec_2022.ValidityPeriod `tlv:"0xFD"`
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
	//+field:natural
	NPsdEntries uint64 `tlv:"0x19D"`
}

// PrefixStateStatusVersion is the current wire version of PrefixStateStatus.
const PrefixStateStatusVersion = uint64(1)

// PrefixStateStatus is a deterministic snapshot of the DV prefix-state database.
type PrefixStateStatus struct {
	//+field:natural
	Version uint64 `tlv:"0x19F"`
	//+field:sequence:*PrefixStateStatusEntry:struct:PrefixStateStatusEntry
	Entries []*PrefixStateStatusEntry `tlv:"0x1A1"`
}

// PrefixStateStatusEntry describes one prefix advertised by one router.
type PrefixStateStatusEntry struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:struct:spec_2022.ValidityPeriod
	ValidityPeriod *spec_2022.ValidityPeriod `tlv:"0xFD"`
	//+field:name
	Router enc.Name `tlv:"0x1A3"`
	//+field:bool
	Multicast bool `tlv:"0x1A5"`
	//+field:sequence:*PrefixStateNextHop:struct:PrefixStateNextHop
	NextHops []*PrefixStateNextHop `tlv:"0x1A7"`
}

// PrefixStateNextHop describes a local next hop for a prefix-state entry.
type PrefixStateNextHop struct {
	//+field:natural
	Face uint64 `tlv:"0x69"`
	//+field:natural
	Cost uint64 `tlv:"0x6A"`
}

type PrefixInsertion struct {
	//+field:sequence:[]byte:binary:[]byte
	StapledCertificates [][]byte `tlv:"0x216"`
	//+field:binary
	Data []byte `tlv:"0x06"`
}

type PrefixInsertionInnerContent struct {
	//+field:struct:spec_2022.ValidityPeriod
	ValidityPeriod *spec_2022.ValidityPeriod `tlv:"0xfd"`
	//+field:natural:optional
	Cost optional.Optional[uint64] `tlv:"0x6a"`
}
