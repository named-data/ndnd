//go:generate gondn_tlv_gen
package tlv

import (
	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

type CaProfile struct {
	//+field:struct:spec.NameContainer
	CaPrefix *spec.NameContainer `tlv:"0x81"`
	//+field:string
	CaInfo string `tlv:"0x83"`
	//+field:sequence:string:string
	ParamKey []string `tlv:"0x85"`
	//+field:natural
	MaxValidPeriod uint64 `tlv:"0x8B"`
	//+field:wire
	CaCert enc.Wire `tlv:"0x89"`
}

type ProbeReq struct {
	//+field:map:string:string:0x87:[]byte:binary
	Params map[string][]byte `tlv:"0x85"`
}

type ProbeResVals struct {
	//+field:name
	Response enc.Name `tlv:"0x07"`
	//+field:natural:optional
	MaxSuffixLength optional.Optional[uint64] `tlv:"0x8F"`
}

type ProbeRes struct {
	//+field:sequence:*ProbeResVals:struct:ProbeResVals
	Vals []*ProbeResVals `tlv:"0x8D"`
	//+field:struct:spec.NameContainer
	RedirectPrefix *spec.NameContainer `tlv:"0xB3"`
}

type NewReq struct {
	//+field:binary
	EcdhPub []byte `tlv:"0x91"`
	//+field:wire
	CertReq enc.Wire `tlv:"0x93"`
}

type NewRes struct {
	//+field:binary
	EcdhPub []byte `tlv:"0x91"`
	//+field:binary
	Salt []byte `tlv:"0x95"`
	//+field:binary
	ReqId []byte `tlv:"0x97"`
	//+field:sequence:string:string
	Challenge []string `tlv:"0x99"`
}

type CipherMsg struct {
	//+field:binary
	InitVec []byte `tlv:"0x9D"`
	//+field:binary
	AuthNTag []byte `tlv:"0xAF"`
	//+field:binary
	Payload []byte `tlv:"0x9F"`
}

type ChallengeReq struct {
	//+field:string
	Challenge string `tlv:"0xA1"`
	//+field:map:string:string:0x87:[]byte:binary
	Params map[string][]byte `tlv:"0x85"`
}

type ChallengeRes struct {
	//+field:natural
	Status uint64 `tlv:"0x9B"`
	//+field:string:optional
	ChalStatus optional.Optional[string] `tlv:"0xA3"`
	//+field:natural:optional
	RemainTries optional.Optional[uint64] `tlv:"0xA5"`
	//+field:natural:optional
	RemainTime optional.Optional[uint64] `tlv:"0xA7"`
	//+field:struct:spec.NameContainer
	CertName *spec.NameContainer `tlv:"0xA9"`
	//+field:struct:spec.NameContainer
	ForwardingHint *spec.NameContainer `tlv:"0x1e"`
	//+field:map:string:string:0x87:[]byte:binary
	Params map[string][]byte `tlv:"0x85"`
}

type ErrorRes struct {
	//+field:natural
	ErrCode uint64 `tlv:"0xAB"`
	//+field:string
	ErrInfo string `tlv:"0xAD"`
}
