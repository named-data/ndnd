//go:generate gondn_tlv_gen
package rdr

import enc "github.com/named-data/ndnd/std/encoding"

const MetadataKeyword = "metadata"

type ManifestDigest struct {
	//+field:natural
	SegNo uint64 `tlv:"0xcc"`
	//+field:binary
	Digest []byte `tlv:"0xce"`
}

type ManifestData struct {
	//+field:sequence:*ManifestDigest:struct:ManifestDigest
	Entries []*ManifestDigest `tlv:"0xca"`
}

type MetaData struct {
	//+field:name
	Name enc.Name `tlv:"0x07"` // Versioned Name
	//+field:binary
	FinalBlockID []byte `tlv:"0x1a"`
	//+field:natural:optional
	SegmentSize enc.Optional[uint64] `tlv:"0xf500"`
	//+field:natural:optional
	Size enc.Optional[uint64] `tlv:"0xf502"`
	//+field:natural:optional
	Mode enc.Optional[uint64] `tlv:"0xf504"`
	//+field:natural:optional
	Atime enc.Optional[uint64] `tlv:"0xf506"`
	//+field:natural:optional
	Btime enc.Optional[uint64] `tlv:"0xf508"`
	//+field:natural:optional
	Ctime enc.Optional[uint64] `tlv:"0xf50a"`
	//+field:natural:optional
	Mtime enc.Optional[uint64] `tlv:"0xf50c"`
	//+field:string:optional
	ObjectType enc.Optional[string] `tlv:"0xf50e"`
}
