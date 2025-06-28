package spec_2022

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// +tlv-model:nocopy,private,ordered
type Interest struct {
	//+field:procedureArgument:enc.Wire
	sigCovered enc.PlaceHolder
	//+field:procedureArgument:enc.Wire
	digestCovered enc.PlaceHolder

	//+field:interestName:sigCovered
	NameV enc.Name `tlv:"0x07"`
	//+field:bool
	CanBePrefixV bool `tlv:"0x21"`
	//+field:bool
	MustBeFreshV bool `tlv:"0x12"`
	//+field:struct:Links
	ForwardingHintV *Links `tlv:"0x1e"`
	//+field:fixedUint:uint32:optional
	NonceV optional.Optional[uint32] `tlv:"0x0a"`
	//+field:time:optional
	InterestLifetimeV optional.Optional[time.Duration] `tlv:"0x0c"`
	//+field:byte
	HopLimitV *byte `tlv:"0x22"`

	//+field:offsetMarker
	sigCoverStart enc.PlaceHolder
	//+field:offsetMarker
	digestCoverStart enc.PlaceHolder

	//+field:wire
	ApplicationParameters enc.Wire `tlv:"0x24"`
	//+field:struct:SignatureInfo
	SignatureInfo *SignatureInfo `tlv:"0x2c"`
	//+field:signature:sigCoverStart:sigCovered
	SignatureValue enc.Wire `tlv:"0x2e"`

	//+field:rangeMarker:digestCoverStart:digestCovered
	digestCoverEnd enc.PlaceHolder
}

type Links struct {
	//+field:sequence:enc.Name:name
	Names []enc.Name `tlv:"0x07"`
}
