package spec_2022

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// +tlv-model:nocopy,private,ordered
type Data struct {
	//+field:procedureArgument:enc.Wire
	sigCovered enc.PlaceHolder
	//+field:offsetMarker
	sigCoverStart enc.PlaceHolder

	//+field:name
	NameV enc.Name `tlv:"0x07"`
	//+field:struct:MetaInfo
	MetaInfo *MetaInfo `tlv:"0x14"`
	//+field:wire
	ContentV enc.Wire `tlv:"0x15"`
	//+field:struct:SignatureInfo
	SignatureInfo *SignatureInfo `tlv:"0x16"`
	//+field:signature:sigCoverStart:sigCovered
	SignatureValue enc.Wire `tlv:"0x17"`

	//+field:wire
	CrossSchemaV enc.Wire `tlv:"0x258"`
}

type MetaInfo struct {
	//+field:natural:optional
	ContentType optional.Optional[uint64] `tlv:"0x18"`
	//+field:time:optional
	FreshnessPeriod optional.Optional[time.Duration] `tlv:"0x19"`
	//+field:binary
	FinalBlockID []byte `tlv:"0x1a"`
}

type SignatureInfo struct {
	//+field:natural
	SignatureType uint64 `tlv:"0x1b"`
	//+field:struct:KeyLocator
	KeyLocator *KeyLocator `tlv:"0x1c"`
	//+field:binary
	SignatureNonce []byte `tlv:"0x26"`
	//+field:time:optional
	SignatureTime optional.Optional[time.Duration] `tlv:"0x28"`
	//+field:natural:optional
	SignatureSeqNum optional.Optional[uint64] `tlv:"0x2a"`
	//+field:struct:ValidityPeriod
	ValidityPeriod *ValidityPeriod `tlv:"0xfd"`
	//+field:struct:CertAdditionalDescription
	AdditionalDescription *CertAdditionalDescription `tlv:"0x0102"`
}

type KeyLocator struct {
	//+field:name
	Name enc.Name `tlv:"0x07"`
	//+field:binary
	KeyDigest []byte `tlv:"0x1d"`
}

type ValidityPeriod struct {
	//+field:string
	NotBefore string `tlv:"0xfe"`
	//+field:string
	NotAfter string `tlv:"0xff"`
}

type CertDescriptionEntry struct {
	//+field:string
	DescriptionKey string `tlv:"0x0201"`
	//+field:string
	DescriptionValue string `tlv:"0x0202"`
}

type CertAdditionalDescription struct {
	//+field:sequence:*CertDescriptionEntry:struct:CertDescriptionEntry
	DescriptionEntries []*CertDescriptionEntry `tlv:"0x0200"`
}
