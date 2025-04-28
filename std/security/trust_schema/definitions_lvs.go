package trust_schema

import "github.com/named-data/ndnd/std/types/optional"

type LvsUserFnArg struct {
	//+field:binary
	Value []byte `tlv:"0x21"`
	//+field:natural:optional
	Tag optional.Optional[uint64] `tlv:"0x23"`
}

type LvsUserFnCall struct {
	//+field:binary
	FnId []byte `tlv:"0x27"`
	//+field:sequence:*LvsUserFnArg:struct:LvsUserFnArg
	Args []*LvsUserFnArg `tlv:"0x33"`
}

type LvsConstraintOption struct {
	//+field:binary
	Value []byte `tlv:"0x21"`
	//+field:natural:optional
	Tag optional.Optional[uint64] `tlv:"0x23"`
	//+field:struct:LvsUserFnCall
	Fn *LvsUserFnCall `tlv:"0x31"`
}

type LvsPatternConstraint struct {
	//+field:sequence:*LvsConstraintOption:struct:LvsConstraintOption
	ConsOptions []*LvsConstraintOption `tlv:"0x41"`
}

type LvsPatternEdge struct {
	//+field:natural
	Dest uint64 `tlv:"0x25"`
	//+field:natural
	Tag uint64 `tlv:"0x23"`
	//+field:sequence:*LvsPatternConstraint:struct:LvsPatternConstraint
	ConsSets []*LvsPatternConstraint `tlv:"0x43"`
}

type LvsValueEdge struct {
	//+field:natural
	Dest uint64 `tlv:"0x25"`
	//+field:binary
	Value []byte `tlv:"0x21"`
}

type LvsNode struct {
	//+field:natural
	Id uint64 `tlv:"0x25"`
	//+field:natural:optional
	Parent optional.Optional[uint64] `tlv:"0x57"`
	//+field:sequence:[]byte:binary:[]byte
	RuleName [][]byte `tlv:"0x29"`
	//+field:sequence:*LvsValueEdge:struct:LvsValueEdge
	Edges []*LvsValueEdge `tlv:"0x51"`
	//+field:sequence:*LvsPatternEdge:struct:LvsPatternEdge
	PatternEdges []*LvsPatternEdge `tlv:"0x53"`
	//+field:sequence:uint64:natural:uint64
	SignCons []uint64 `tlv:"0x55"`
}

type LvsTagSymbol struct {
	//+field:natural:optional
	Tag optional.Optional[uint64] `tlv:"0x23"`
	//+field:binary
	Ident []byte `tlv:"0x29"`
}

type LvsModel struct {
	//+field:natural
	Version uint64 `tlv:"0x61"`
	//+field:natural
	StartId uint64 `tlv:"0x25"`
	//+field:natural
	NamedPatternCnt uint64 `tlv:"0x69"`
	//+field:sequence:*LvsNode:struct:LvsNode
	Nodes []*LvsNode `tlv:"0x63"`
	//+field:sequence:*LvsTagSymbol:struct:LvsTagSymbol
	Symbols []*LvsTagSymbol `tlv:"0x67"`
}
