package spec_2022

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

const (
	NackReasonNone       = uint64(0)
	NackReasonCongestion = uint64(50)
	NackReasonDuplicate  = uint64(100)
	NackReasonNoRoute    = uint64(150)
)

// +tlv-model:nocopy,private
type LpPacket struct {
	//+field:fixedUint:uint64:optional
	Sequence optional.Optional[uint64] `tlv:"0x51"`
	//+field:natural:optional
	FragIndex optional.Optional[uint64] `tlv:"0x52"`
	//+field:natural:optional
	FragCount optional.Optional[uint64] `tlv:"0x53"`
	//+field:binary
	PitToken []byte `tlv:"0x62"`
	//+field:struct:NetworkNack
	Nack *NetworkNack `tlv:"0x0320"`
	//+field:natural:optional
	IncomingFaceId optional.Optional[uint64] `tlv:"0x032C"`
	//+field:natural:optional
	NextHopFaceId optional.Optional[uint64] `tlv:"0x0330"`
	//+field:struct:CachePolicy
	CachePolicy *CachePolicy `tlv:"0x0334"`
	//+field:natural:optional
	CongestionMark optional.Optional[uint64] `tlv:"0x0340"`
	//+field:fixedUint:uint64:optional
	Ack optional.Optional[uint64] `tlv:"0x0344"`
	//+field:fixedUint:uint64:optional
	TxSequence optional.Optional[uint64] `tlv:"0x0348"`
	//+field:bool
	NonDiscovery bool `tlv:"0x034C"`
	//+field:wire
	PrefixAnnouncement enc.Wire `tlv:"0x0350"`

	//+field:wire
	Fragment enc.Wire `tlv:"0x50"`
}

type NetworkNack struct {
	//+field:natural
	Reason uint64 `tlv:"0x0321"`
}

type CachePolicy struct {
	//+field:natural
	CachePolicyType uint64 `tlv:"0x0335"`
}
