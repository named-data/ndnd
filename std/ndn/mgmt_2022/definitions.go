//go:generate gondn_tlv_gen
package mgmt_2022

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

const (
	FaceScopeNonLocal = uint64(0)
	FaceScopeLocal    = uint64(1)
)

const (
	FacePersPersistent = uint64(0)
	FacePersOnDemand   = uint64(1)
	FacePersPermanent  = uint64(2)
)

const (
	FaceLinkPointToPoint = uint64(0)
	FaceLinkMultiAccess  = uint64(1)
	FaceLinkAdHoc        = uint64(2)
)

const (
	FaceFlagNoFlag                   = uint64(0)
	FaceFlagLocalFieldsEnabled       = uint64(1)
	FaceFlagLpReliabilityEnabled     = uint64(2)
	FaceFlagCongestionMarkingEnabled = uint64(4)
)

const (
	FaceEventCreated   = uint64(1)
	FaceEventDestroyed = uint64(2)
	FaceEventUp        = uint64(3)
	FaceEventDown      = uint64(4)
)

const (
	CsFlagNone    = uint64(0)
	CsEnableAdmit = uint64(1)
	CsEnableServe = uint64(2)
)

// +tlv-model:dict
type Strategy struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
}

// +tlv-model:dict
type ControlArgs struct {
	// Note: go-ndn generator does not support inheritance yet.

	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:natural:optional
	FaceId optional.Optional[uint64] `tlv:"0x69"`
	//+field:string:optional
	Uri optional.Optional[string] `tlv:"0x72"`
	//+field:string:optional
	LocalUri optional.Optional[string] `tlv:"0x81"`
	//+field:natural:optional
	Origin optional.Optional[uint64] `tlv:"0x6f"`
	//+field:natural:optional
	Cost optional.Optional[uint64] `tlv:"0x6a"`
	//+field:natural:optional
	Capacity optional.Optional[uint64] `tlv:"0x83"`
	//+field:natural:optional
	Count optional.Optional[uint64] `tlv:"0x84"`
	//+field:natural:optional
	Flags optional.Optional[uint64] `tlv:"0x6c"`
	//+field:natural:optional
	Mask optional.Optional[uint64] `tlv:"0x70"`
	//+field:struct:Strategy
	Strategy *Strategy `tlv:"0x6b"`
	//+field:natural:optional
	ExpirationPeriod optional.Optional[uint64] `tlv:"0x6d"`
	//+field:natural:optional
	FacePersistency optional.Optional[uint64] `tlv:"0x85"`
	//+field:natural:optional
	BaseCongestionMarkInterval optional.Optional[uint64] `tlv:"0x87"`
	//+field:natural:optional
	DefaultCongestionThreshold optional.Optional[uint64] `tlv:"0x88"`
	//+field:natural:optional
	Mtu optional.Optional[uint64] `tlv:"0x89"`
}

// +tlv-model:dict
type ControlResponseVal struct {
	//+field:natural
	StatusCode uint64 `tlv:"0x66"`
	//+field:string
	StatusText string `tlv:"0x67"`
	//+field:struct:ControlArgs
	Params *ControlArgs `tlv:"0x68"`
}

type ControlParameters struct {
	//+field:struct:ControlArgs
	Val *ControlArgs `tlv:"0x68"`
}

type ControlResponse struct {
	//+field:struct:ControlResponseVal
	Val *ControlResponseVal `tlv:"0x65"`
}

type FaceEventNotificationValue struct {
	//+field:natural
	FaceEventKind uint64 `tlv:"0xc1"`
	//+field:natural
	FaceId uint64 `tlv:"0x69"`
	//+field:string
	Uri string `tlv:"0x72"`
	//+field:string
	LocalUri string `tlv:"0x81"`
	//+field:natural
	FaceScope uint64 `tlv:"0x84"`
	//+field:natural
	FacePersistency uint64 `tlv:"0x85"`
	//+field:natural
	LinkType uint64 `tlv:"0x86"`
	//+field:natural
	Flags uint64 `tlv:"0x6c"`
}

type FaceEventNotification struct {
	//+field:struct:FaceEventNotificationValue
	Val *FaceEventNotificationValue `tlv:"0xc0"`
}

type GeneralStatus struct {
	//+field:string
	NfdVersion string `tlv:"0x80"`
	//+field:time
	StartTimestamp time.Duration `tlv:"0x81"`
	//+field:time
	CurrentTimestamp time.Duration `tlv:"0x82"`
	//+field:natural
	NNameTreeEntries uint64 `tlv:"0x83"`
	//+field:natural
	NFibEntries uint64 `tlv:"0x84"`
	//+field:natural
	NPitEntries uint64 `tlv:"0x85"`
	//+field:natural
	NMeasurementsEntries uint64 `tlv:"0x86"`
	//+field:natural
	NCsEntries uint64 `tlv:"0x87"`
	//+field:natural
	NInInterests uint64 `tlv:"0x90"`
	//+field:natural
	NInData uint64 `tlv:"0x91"`
	//+field:natural
	NInNacks uint64 `tlv:"0x97"`
	//+field:natural
	NOutInterests uint64 `tlv:"0x92"`
	//+field:natural
	NOutData uint64 `tlv:"0x93"`
	//+field:natural
	NOutNacks uint64 `tlv:"0x98"`
	//+field:natural
	NSatisfiedInterests uint64 `tlv:"0x99"`
	//+field:natural
	NUnsatisfiedInterests uint64 `tlv:"0x9a"`

	//+field:natural:optional
	NFragmentationError optional.Optional[uint64] `tlv:"0xc8"`
	//+field:natural:optional
	NOutOverMtu optional.Optional[uint64] `tlv:"0xc9"`
	//+field:natural:optional
	NInLpInvalid optional.Optional[uint64] `tlv:"0xca"`
	//+field:natural:optional
	NReassemblyTimeouts optional.Optional[uint64] `tlv:"0xcb"`
	//+field:natural:optional
	NInNetInvalid optional.Optional[uint64] `tlv:"0xcc"`
	//+field:natural:optional
	NAcknowledged optional.Optional[uint64] `tlv:"0xcd"`
	//+field:natural:optional
	NRetransmitted optional.Optional[uint64] `tlv:"0xce"`
	//+field:natural:optional
	NRetxExhausted optional.Optional[uint64] `tlv:"0xcf"`
	//+field:natural:optional
	NConngestionMarked optional.Optional[uint64] `tlv:"0xd0"`
}

type FaceStatus struct {
	//+field:natural
	FaceId uint64 `tlv:"0x69"`
	//+field:string
	Uri string `tlv:"0x72"`
	//+field:string
	LocalUri string `tlv:"0x81"`
	//+field:natural:optional
	ExpirationPeriod optional.Optional[uint64] `tlv:"0x6d"`
	//+field:natural
	FaceScope uint64 `tlv:"0x84"`
	//+field:natural
	FacePersistency uint64 `tlv:"0x85"`
	//+field:natural
	LinkType uint64 `tlv:"0x86"`
	//+field:natural:optional
	BaseCongestionMarkInterval optional.Optional[uint64] `tlv:"0x87"`
	//+field:natural:optional
	DefaultCongestionThreshold optional.Optional[uint64] `tlv:"0x88"`
	//+field:natural:optional
	Mtu optional.Optional[uint64] `tlv:"0x89"`

	//+field:natural
	NInInterests uint64 `tlv:"0x90"`
	//+field:natural
	NInData uint64 `tlv:"0x91"`
	//+field:natural
	NInNacks uint64 `tlv:"0x97"`
	//+field:natural
	NOutInterests uint64 `tlv:"0x92"`
	//+field:natural
	NOutData uint64 `tlv:"0x93"`
	//+field:natural
	NOutNacks uint64 `tlv:"0x98"`
	//+field:natural
	NInBytes uint64 `tlv:"0x94"`
	//+field:natural
	NOutBytes uint64 `tlv:"0x95"`

	//+field:natural
	Flags uint64 `tlv:"0x6c"`
}

type FaceStatusMsg struct {
	//+field:sequence:*FaceStatus:struct:FaceStatus
	Vals []*FaceStatus `tlv:"0x80"`
}

type FaceQueryFilterValue struct {
	//+field:natural:optional
	FaceId optional.Optional[uint64] `tlv:"0x69"`
	//+field:string:optional
	UriScheme optional.Optional[string] `tlv:"0x83"`
	//+field:string:optional
	Uri optional.Optional[string] `tlv:"0x72"`
	//+field:string:optional
	LocalUri optional.Optional[string] `tlv:"0x81"`
	//+field:natural:optional
	FaceScope optional.Optional[uint64] `tlv:"0x84"`
	//+field:natural:optional
	FacePersistency optional.Optional[uint64] `tlv:"0x85"`
	//+field:natural:optional
	LinkType optional.Optional[uint64] `tlv:"0x86"`
}

type FaceQueryFilter struct {
	//+field:struct:FaceQueryFilterValue
	Val *FaceQueryFilterValue `tlv:"0x96"`
}

type Route struct {
	//+field:natural
	FaceId uint64 `tlv:"0x69"`
	//+field:natural
	Origin uint64 `tlv:"0x6f"`
	//+field:natural
	Cost uint64 `tlv:"0x6a"`
	//+field:natural
	Flags uint64 `tlv:"0x6c"`
	//+field:natural:optional
	ExpirationPeriod optional.Optional[uint64] `tlv:"0x6d"`
}

type RibEntry struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:sequence:*Route:struct:Route
	Routes []*Route `tlv:"0x81"`
}

type RibStatus struct {
	//+field:sequence:*RibEntry:struct:RibEntry
	Entries []*RibEntry `tlv:"0x80"`
}

type NextHopRecord struct {
	//+field:natural
	FaceId uint64 `tlv:"0x69"`
	//+field:natural
	Cost uint64 `tlv:"0x6a"`
}

type FibEntry struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:sequence:*NextHopRecord:struct:NextHopRecord
	NextHopRecords []*NextHopRecord `tlv:"0x81"`
}

type FibStatus struct {
	//+field:sequence:*FibEntry:struct:FibEntry
	Entries []*FibEntry `tlv:"0x80"`
}

type StrategyChoice struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:struct:Strategy
	Strategy *Strategy `tlv:"0x6b"`
}

type StrategyChoiceMsg struct {
	//+field:sequence:*StrategyChoice:struct:StrategyChoice
	StrategyChoices []*StrategyChoice `tlv:"0x80"`
}

type CsInfo struct {
	//+field:natural
	Capacity uint64 `tlv:"0x83"`
	//+field:natural
	Flags uint64 `tlv:"0x6c"`
	//+field:natural
	NCsEntries uint64 `tlv:"0x87"`
	//+field:natural
	NHits uint64 `tlv:"0x81"`
	//+field:natural
	NMisses uint64 `tlv:"0x82"`
}

type CsInfoMsg struct {
	//+field:struct:CsInfo
	CsInfo *CsInfo `tlv:"0x80"`
}

// No Tlv numbers assigned yet
type CsQuery struct {
	Name            enc.Name
	PacketSize      uint64
	FreshnessPeriod uint64
}
