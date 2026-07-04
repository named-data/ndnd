//go:generate gondn_tlv_gen
package revocationtlv

import "github.com/named-data/ndnd/std/types/optional"

// RevocationRecord content TLVs per UCLA-IRL/ndnrevoke.
//
// +tlv-model:ordered
type RevocationRecord struct {
	//+field:natural
	Timestamp uint64 `tlv:"0xC9"`
	//+field:natural
	Reason uint64 `tlv:"0xCB"`
	//+field:binary
	PublicKeyHash []byte `tlv:"0xCA"`
	//+field:natural:optional
	NotBefore optional.Optional[uint64] `tlv:"0xCD"`
}
