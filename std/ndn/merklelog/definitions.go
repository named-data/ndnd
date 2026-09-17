//go:generate gondn_tlv_gen
package merklelog

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// TypeLogEntry is the outer TLV type included in every Merkle leaf hash.
const TypeLogEntry enc.TLNum = 0x1E12

const (
	// AppendStatusOK indicates that the hash was added to a new log entry.
	AppendStatusOK uint64 = iota
	// AppendStatusDuplicate indicates that the hash already has a log entry.
	AppendStatusDuplicate
	// AppendStatusFailed indicates that the hash could not be logged.
	AppendStatusFailed
)

const (
	// CheckStatusIncluded indicates that the response contains an inclusion proof.
	CheckStatusIncluded uint64 = iota
	// CheckStatusNotFound indicates that the hash is absent from the returned tree.
	CheckStatusNotFound
)

type AppendRequest struct {
	//+field:sequence:[]byte:binary:[]byte
	DataHashes [][]byte `tlv:"0x1E00"`
}

type AppendResponse struct {
	//+field:sequence:*AppendResult:struct:AppendResult
	Results []*AppendResult `tlv:"0x1E02"`
}

type AppendResult struct {
	//+field:binary
	DataHash []byte `tlv:"0x1E00"`
	//+field:natural
	Status uint64 `tlv:"0x1E04"`
	//+field:natural:optional
	LeafIndex optional.Optional[uint64] `tlv:"0x1E06"`
}

type CheckResponse struct {
	//+field:struct:TreeRoot
	Root *TreeRoot `tlv:"0x1E08"`
	//+field:struct:CheckResult
	Result *CheckResult `tlv:"0x1E0A"`
}

type CheckResult struct {
	//+field:binary
	DataHash []byte `tlv:"0x1E00"`
	//+field:natural
	Status uint64 `tlv:"0x1E04"`
	//+field:struct:InclusionProof
	Proof *InclusionProof `tlv:"0x1E0C"`
}

type TreeRoot struct {
	//+field:natural
	TreeSize uint64 `tlv:"0x1E0E"`
	//+field:binary
	RootHash []byte `tlv:"0x1E10"`
}

type InclusionProof struct {
	// Entry contains the unmodified TLV-VALUE of the proven LogEntry. Keeping
	// this as wire allows the verifier to reconstruct and hash the exact entry
	// encoding instead of re-encoding parsed fields.
	//+field:wire
	Entry enc.Wire `tlv:"0x1E12"`
	//+field:natural
	LeafIndex uint64 `tlv:"0x1E06"`
	//+field:sequence:[]byte:binary:[]byte
	SiblingHashes [][]byte `tlv:"0x1E14"`
}

type LogEntry struct {
	// IngestTime is the log-assigned Unix timestamp, represented at millisecond
	// precision as a duration since the Unix epoch.
	//+field:time
	IngestTime time.Duration `tlv:"0x1E16"`
	//+field:sequence:[]byte:binary:[]byte
	DataHashes [][]byte `tlv:"0x1E00"`
}
