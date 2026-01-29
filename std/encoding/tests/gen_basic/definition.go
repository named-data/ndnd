//go:generate gondn_tlv_gen
package gen_basic

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

type FakeMetaInfo struct {
	//+field:natural
	Number uint64 `tlv:"0x18"`
	//+field:time
	Time time.Duration `tlv:"0x19"`
	//+field:binary
	Binary []byte `tlv:"0x1a"`
}

type OptField struct {
	//+field:natural:optional
	Number optional.Optional[uint64] `tlv:"0x18"`
	//+field:time:optional
	Time optional.Optional[time.Duration] `tlv:"0x19"`
	//+field:binary
	Binary []byte `tlv:"0x1a"`
	//+field:bool
	Bool bool `tlv:"0x30"`
}

type WireNameField struct {
	//+field:wire
	Wire enc.Wire `tlv:"0x01"`
	//+field:name
	Name enc.Name `tlv:"0x02"`
}

// +tlv-model:private,ordered
type Markers struct {
	//+field:offsetMarker
	startMarker enc.PlaceHolder
	//+field:wire
	Wire enc.Wire `tlv:"0x01"`
	//+field:procedureArgument:int
	argument enc.PlaceHolder
	//+field:name
	Name enc.Name `tlv:"0x02"`
	//+field:offsetMarker
	endMarker enc.PlaceHolder
}

// (AI GENERATED DESCRIPTION): Encodes the Markers instance into a wire‑formatted byte slice using the supplied argument and returns the result only if the markers span the entire slice.
func (m *Markers) Encode(arg int) []byte {
	enc := MarkersEncoder{}
	enc.Init(m)
	enc.argument = arg
	wire := enc.Encode(m)
	ret := wire.Join()
	if enc.startMarker != 0 {
		return nil
	}
	if enc.endMarker != len(ret) {
		return nil
	}
	return ret
}

// (AI GENERATED DESCRIPTION): Parses a byte slice into markers, returning a Markers object only if the entire slice is successfully parsed without error; otherwise it returns nil.
func ParseMarkers(buf []byte, arg int) *Markers {
	cont := MarkersParsingContext{
		argument: arg,
	}
	cont.Init()
	ret, err := cont.Parse(enc.NewBufferView(buf), true)
	if err == nil && cont.startMarker == 0 && cont.endMarker == len(buf) {
		return ret
	} else {
		return nil
	}
}

// +tlv-model:nocopy
type NoCopyStruct struct {
	//+field:wire
	Wire1 enc.Wire `tlv:"0x01"`
	//+field:natural
	Number uint64 `tlv:"0x02"`
	//+field:wire
	Wire2 enc.Wire `tlv:"0x03"`
}

type StrField struct {
	//+field:string
	Str1 string `tlv:"0x01"`
	//+field:string:optional
	Str2 optional.Optional[string] `tlv:"0x02"`
}

type FixedUintField struct {
	//+field:fixedUint:byte
	Byte byte `tlv:"0x01"`
	//+field:fixedUint:uint32:optional
	U32 optional.Optional[uint32] `tlv:"0x02"`
	//+field:fixedUint:uint64:optional
	U64 optional.Optional[uint64] `tlv:"0x03"`
	//+field:byte
	BytePtr *byte `tlv:"0x04"`
}
