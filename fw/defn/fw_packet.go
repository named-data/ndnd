//go:generate gondn_tlv_gen
package defn

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// +tlv-model:nocopy
type FwPacket struct {
	//+field:struct:FwInterest:nocopy
	Interest *FwInterest `tlv:"0x05"`
	//+field:struct:FwData:nocopy
	Data *FwData `tlv:"0x06"`
	//+field:struct:FwLpPacket:nocopy
	LpPacket *FwLpPacket `tlv:"0x64"`
}

// +tlv-model:nocopy
type FwInterest struct {
	//+field:name
	NameV enc.Name `tlv:"0x07"`
	//+field:bool
	CanBePrefixV bool `tlv:"0x21"`
	//+field:bool
	MustBeFreshV bool `tlv:"0x12"`
	//+field:struct:FwLinks
	ForwardingHintV *FwLinks `tlv:"0x1e"`
	//+field:fixedUint:uint32:optional
	NonceV optional.Optional[uint32] `tlv:"0x0a"`
	//+field:time:optional
	InterestLifetimeV optional.Optional[time.Duration] `tlv:"0x0c"`
	//+field:byte
	HopLimitV *byte `tlv:"0x22"`

	//+field:bool
	ApplicationParameters bool `tlv:"0x24"`
	//+field:bool
	SignatureInfo bool `tlv:"0x2c"`
	//+field:bool
	SignatureValue bool `tlv:"0x2e"`
}

type FwLinks struct {
	//+field:sequence:enc.Name:name
	Names []enc.Name `tlv:"0x07"`
}

// +tlv-model:nocopy
type FwData struct {
	//+field:name
	NameV enc.Name `tlv:"0x07"`
	//+field:struct:FwMetaInfo
	MetaInfo *FwMetaInfo `tlv:"0x14"`

	//+field:bool
	ContentV bool `tlv:"0x15"`
	//+field:bool
	SignatureInfo bool `tlv:"0x16"`
	//+field:bool
	SignatureValue bool `tlv:"0x17"`
}

type FwMetaInfo struct {
	//+field:natural:optional
	ContentType optional.Optional[uint64] `tlv:"0x18"`
	//+field:time:optional
	FreshnessPeriod optional.Optional[time.Duration] `tlv:"0x19"`

	//+field:bool
	FinalBlockID bool `tlv:"0x1a"`
}

// +tlv-model:nocopy
type FwLpPacket struct {
	//+field:fixedUint:uint64:optional
	Sequence optional.Optional[uint64] `tlv:"0x51"`
	//+field:natural:optional
	FragIndex optional.Optional[uint64] `tlv:"0x52"`
	//+field:natural:optional
	FragCount optional.Optional[uint64] `tlv:"0x53"`
	//+field:binary
	PitToken []byte `tlv:"0x62"`
	//+field:struct:FwNetworkNack
	Nack *FwNetworkNack `tlv:"0x0320"`
	//+field:natural:optional
	IncomingFaceId optional.Optional[uint64] `tlv:"0x032C"`
	//+field:natural:optional
	NextHopFaceId optional.Optional[uint64] `tlv:"0x0330"`
	//+field:struct:FwCachePolicy
	CachePolicy *FwCachePolicy `tlv:"0x0334"`
	//+field:natural:optional
	CongestionMark optional.Optional[uint64] `tlv:"0x0340"`

	//+field:wire
	Fragment enc.Wire `tlv:"0x50"`
}

type FwNetworkNack struct {
	//+field:natural
	Reason uint64 `tlv:"0x0321"`
}

type FwCachePolicy struct {
	//+field:natural
	CachePolicyType uint64 `tlv:"0x0335"`
}

// (AI GENERATED DESCRIPTION): Returns the Name value (`NameV`) stored in a forwarded Interest packet.
func (p *FwInterest) Name() enc.Name {
	return p.NameV
}

// (AI GENERATED DESCRIPTION): Returns the optional lifetime value of this Interest packet, if one has been set.
func (p *FwInterest) Lifetime() optional.Optional[time.Duration] {
	return p.InterestLifetimeV
}
