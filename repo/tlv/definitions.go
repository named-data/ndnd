//go:generate gondn_tlv_gen
package tlv

import (
	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

var SyncProtocolSvsV3 = enc.Name{
	enc.NewKeywordComponent("ndn"),
	enc.NewKeywordComponent("svs"),
	enc.NewVersionComponent(3),
}

type RepoCmd struct {
	//+field:struct:SyncJoin
	SyncJoin *SyncJoin `tlv:"0x1DB0"`
	//+field:struct:SyncLeave
	SyncLeave *SyncLeave `tlv:"0x1DB1"`
	//+field:struct:BlobFetch
	BlobFetch *BlobFetch `tlv:"0x1DB2"`
}

type RepoCmdRes struct {
	//+field:natural
	Status uint64 `tlv:"0x291"`
	//+field:string
	Message string `tlv:"0x292"`
}

type SyncJoin struct {
	//+field:struct:spec.NameContainer
	Protocol *spec.NameContainer `tlv:"0x191"`
	//+field:struct:spec.NameContainer
	Group *spec.NameContainer `tlv:"0x193"`
	//+field:struct:spec.NameContainer
	MulticastPrefix *spec.NameContainer `tlv:"0x194"`
	//+field:struct:HistorySnapshotConfig
	HistorySnapshot *HistorySnapshotConfig `tlv:"0x1A4"`
	//+field:struct:spec.NameContainer
	SecurityConfig *spec.NameContainer `tlv:"0x1DB4"`
}

type SyncLeave struct {
	//+field:struct:spec.NameContainer
	Protocol *spec.NameContainer `tlv:"0x191"`
	//+field:struct:spec.NameContainer
	Group *spec.NameContainer `tlv:"0x193"`
}

type HistorySnapshotConfig struct {
	//+field:natural
	Threshold uint64 `tlv:"0x1A5"`
}

type BlobFetch struct {
	//+field:struct:spec.NameContainer
	Name *spec.NameContainer `tlv:"0x1B8"`
	//+field:sequence:[]byte:binary:[]byte
	Data [][]byte `tlv:"0x1BA"`
}

type SecurityConfigObject struct {
	//+field:sequence:[]byte:binary:[]byte
	Schema []byte `tlv:"0x1A5"`
	//+field:sequence:[]byte:binary:[]byte
	Anchors [][]byte `tlv:"0x1BA"`
}
