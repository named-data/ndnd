// Package merklelog implements the cryptographic core of the Merkle history log.
package merklelog

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
)

// HashSize is the size of every leaf, node, and Data hash in bytes.
const HashSize = sha256.Size

var (
	// ErrDuplicateDataHash indicates that a Data hash already belongs to a leaf.
	ErrDuplicateDataHash = errors.New("data hash is already logged")
	// ErrStoreCorrupt indicates that persisted state is internally inconsistent.
	ErrStoreCorrupt = errors.New("merkle log store is corrupt")
	// ErrStoreStateChanged indicates that the persisted tree changed unexpectedly.
	ErrStoreStateChanged = errors.New("merkle log store state changed")
)

// Tree is an append-only Merkle tree. It keeps proof material in memory and may
// optionally persist each append through a Store. Tree is not safe for
// concurrent use; the log service is responsible for serializing appends.
type Tree struct {
	store          Store
	entries        [][]byte
	leafHashes     [][]byte
	dataIndex      map[[HashSize]byte]uint64
	frontier       [][]byte
	lastIngestTime time.Duration
}

// NewTree creates an empty in-memory Merkle tree.
func NewTree() *Tree {
	return &Tree{dataIndex: make(map[[HashSize]byte]uint64)}
}

// OpenTree restores a Merkle tree from store and verifies all persisted state.
func OpenTree(store Store) (*Tree, error) {
	if store == nil {
		return nil, fmt.Errorf("merkle log store is nil")
	}
	snapshot, err := store.Load()
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, fmt.Errorf("%w: store returned a nil snapshot", ErrStoreCorrupt)
	}
	if uint64(len(snapshot.Entries)) != snapshot.State.TreeSize {
		return nil, fmt.Errorf(
			"%w: state has %d leaves but store returned %d entries",
			ErrStoreCorrupt,
			snapshot.State.TreeSize,
			len(snapshot.Entries),
		)
	}

	tree := NewTree()
	for i, entryWire := range snapshot.Entries {
		if _, err := tree.Append(entryWire); err != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", ErrStoreCorrupt, i, err)
		}
	}
	if !equalStoreState(tree.storeState(), snapshot.State) {
		return nil, fmt.Errorf("%w: persisted tree state does not match entries", ErrStoreCorrupt)
	}
	if !equalDataIndex(tree.dataIndex, snapshot.DataIndex) {
		return nil, fmt.Errorf("%w: persisted Data hash index does not match entries", ErrStoreCorrupt)
	}

	tree.store = store
	return tree, nil
}

// Size returns the number of entries in the tree.
func (t *Tree) Size() uint64 {
	return uint64(len(t.entries))
}

// LastIngestTime returns the latest log-assigned ingestion time. The boolean is
// false when the tree is empty.
func (t *Tree) LastIngestTime() (time.Duration, bool) {
	return t.lastIngestTime, t.Size() > 0
}

// Lookup returns the leaf containing dataHash.
func (t *Tree) Lookup(dataHash []byte) (uint64, bool) {
	if len(dataHash) != HashSize {
		return 0, false
	}
	leafIndex, ok := t.dataIndex[dataHashKey(dataHash)]
	return leafIndex, ok
}

// Append adds one raw LogEntry TLV and returns its zero-based leaf index.
func (t *Tree) Append(entryWire []byte) (uint64, error) {
	entry, _, err := decodeLogEntry(entryWire)
	if err != nil {
		return 0, err
	}
	if t.Size() > 0 && entry.IngestTime <= t.lastIngestTime {
		return 0, fmt.Errorf(
			"ingestion time %s is not later than %s",
			entry.IngestTime,
			t.lastIngestTime,
		)
	}

	seen := make(map[[HashSize]byte]struct{}, len(entry.DataHashes))
	for _, dataHash := range entry.DataHashes {
		key := dataHashKey(dataHash)
		if _, ok := seen[key]; ok {
			return 0, fmt.Errorf("%w: duplicate within entry", ErrDuplicateDataHash)
		}
		if leafIndex, ok := t.dataIndex[key]; ok {
			return 0, fmt.Errorf("%w at leaf %d", ErrDuplicateDataHash, leafIndex)
		}
		seen[key] = struct{}{}
	}

	ownedWire := bytes.Clone(entryWire)
	leafHash := hashLeaf(ownedWire)
	nextFrontier := appendFrontier(t.frontier, leafHash)
	leafIndex := t.Size()
	nextState := StoreState{
		TreeSize:       leafIndex + 1,
		RootHash:       rootFromFrontier(nextFrontier),
		Frontier:       nextFrontier,
		LastIngestTime: entry.IngestTime,
	}
	if t.store != nil {
		err = t.store.Append(StoreAppend{
			ExpectedSize: leafIndex,
			EntryWire:    ownedWire,
			State:        nextState,
		})
		if err != nil {
			return 0, err
		}
	}

	t.entries = append(t.entries, ownedWire)
	t.leafHashes = append(t.leafHashes, leafHash)
	for key := range seen {
		t.dataIndex[key] = leafIndex
	}
	t.frontier = nextFrontier
	t.lastIngestTime = entry.IngestTime
	return leafIndex, nil
}

// Root returns the current tree size and root hash. The empty-tree root is
// SHA-256 of the empty byte string.
func (t *Tree) Root() *defn.TreeRoot {
	return &defn.TreeRoot{
		TreeSize: t.Size(),
		RootHash: rootFromFrontier(t.frontier),
	}
}

// InclusionProof returns the raw entry and bottom-up sibling path for leafIndex.
func (t *Tree) InclusionProof(leafIndex uint64) (*defn.InclusionProof, error) {
	if leafIndex >= t.Size() {
		return nil, fmt.Errorf("leaf index %d is outside tree of size %d", leafIndex, t.Size())
	}
	_, entryValue, err := decodeLogEntry(t.entries[leafIndex])
	if err != nil {
		return nil, fmt.Errorf("%w: entry %d: %v", ErrStoreCorrupt, leafIndex, err)
	}

	return &defn.InclusionProof{
		Entry:         enc.Wire{entryValue},
		LeafIndex:     leafIndex,
		SiblingHashes: inclusionPath(t.leafHashes, leafIndex),
	}, nil
}

// EncodeLogEntry returns the complete canonical LogEntry TLV.
func EncodeLogEntry(entry *defn.LogEntry) ([]byte, error) {
	if err := validateEntry(entry); err != nil {
		return nil, err
	}
	return wrapLogEntryValue(entry.Bytes()), nil
}

// ParseLogEntry parses and validates one complete canonical LogEntry TLV.
func ParseLogEntry(entryWire []byte) (*defn.LogEntry, error) {
	entry, _, err := decodeLogEntry(entryWire)
	return entry, err
}

// ParseProofEntry parses and validates the raw LogEntry carried by proof.
func ParseProofEntry(proof *defn.InclusionProof) (*defn.LogEntry, error) {
	if proof == nil {
		return nil, fmt.Errorf("inclusion proof is nil")
	}
	entry, _, err := decodeLogEntry(wrapLogEntryValue(proof.Entry.Join()))
	return entry, err
}

// LeafHash computes SHA-256(0x00 || rawLogEntryTLV).
func LeafHash(entryWire []byte) ([]byte, error) {
	if _, _, err := decodeLogEntry(entryWire); err != nil {
		return nil, err
	}
	return hashLeaf(entryWire), nil
}

// VerifyInclusion verifies that dataHash occurs in the raw proof entry and that
// the entry's inclusion path reconstructs root.
func VerifyInclusion(dataHash []byte, proof *defn.InclusionProof, root *defn.TreeRoot) error {
	if len(dataHash) != HashSize {
		return fmt.Errorf("data hash length is %d, want %d", len(dataHash), HashSize)
	}
	if proof == nil {
		return fmt.Errorf("inclusion proof is nil")
	}
	if root == nil {
		return fmt.Errorf("tree root is nil")
	}
	if root.TreeSize == 0 {
		return fmt.Errorf("an empty tree cannot contain an inclusion proof")
	}
	if len(root.RootHash) != HashSize {
		return fmt.Errorf("root hash length is %d, want %d", len(root.RootHash), HashSize)
	}
	if proof.LeafIndex >= root.TreeSize {
		return fmt.Errorf("leaf index %d is outside tree of size %d", proof.LeafIndex, root.TreeSize)
	}

	entryWire := wrapLogEntryValue(proof.Entry.Join())
	entry, _, err := decodeLogEntry(entryWire)
	if err != nil {
		return fmt.Errorf("invalid proof entry: %w", err)
	}
	found := false
	for _, entryHash := range entry.DataHashes {
		if bytes.Equal(dataHash, entryHash) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("data hash is not present in proof entry")
	}
	for i, siblingHash := range proof.SiblingHashes {
		if len(siblingHash) != HashSize {
			return fmt.Errorf("sibling hash %d length is %d, want %d", i, len(siblingHash), HashSize)
		}
	}

	proofRoot, err := rootFromInclusionPath(
		hashLeaf(entryWire),
		proof.LeafIndex,
		root.TreeSize,
		proof.SiblingHashes,
	)
	if err != nil {
		return err
	}
	if !bytes.Equal(proofRoot, root.RootHash) {
		return fmt.Errorf("inclusion proof does not match tree root")
	}
	return nil
}

func decodeLogEntry(entryWire []byte) (*defn.LogEntry, []byte, error) {
	reader := enc.NewBufferView(entryWire)
	typ, err := reader.ReadTLNum()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read LogEntry type: %w", err)
	}
	if typ != defn.TypeLogEntry {
		return nil, nil, fmt.Errorf("LogEntry type is %d, want %d", typ, defn.TypeLogEntry)
	}
	length, err := reader.ReadTLNum()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read LogEntry length: %w", err)
	}
	if length != enc.TLNum(reader.Length()-reader.Pos()) {
		return nil, nil, fmt.Errorf(
			"LogEntry length is %d, but %d bytes remain",
			length,
			reader.Length()-reader.Pos(),
		)
	}
	entryValue, err := reader.ReadBuf(int(length))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read LogEntry value: %w", err)
	}
	entry, err := defn.ParseLogEntry(enc.NewBufferView(entryValue), false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse LogEntry: %w", err)
	}
	if err := validateEntry(entry); err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(entryWire, wrapLogEntryValue(entry.Bytes())) {
		return nil, nil, fmt.Errorf("LogEntry TLV is not canonical")
	}
	return entry, bytes.Clone(entryValue), nil
}

func validateEntry(entry *defn.LogEntry) error {
	if entry == nil {
		return fmt.Errorf("LogEntry is nil")
	}
	if entry.IngestTime < 0 {
		return fmt.Errorf("ingestion time cannot be negative")
	}
	if entry.IngestTime%time.Millisecond != 0 {
		return fmt.Errorf("ingestion time must have millisecond precision")
	}
	if len(entry.DataHashes) == 0 {
		return fmt.Errorf("LogEntry has no Data hashes")
	}
	for i, dataHash := range entry.DataHashes {
		if len(dataHash) != HashSize {
			return fmt.Errorf("Data hash %d length is %d, want %d", i, len(dataHash), HashSize)
		}
	}
	return nil
}

func wrapLogEntryValue(entryValue []byte) []byte {
	typLen := defn.TypeLogEntry.EncodingLength()
	length := enc.TLNum(len(entryValue))
	ret := make([]byte, typLen+length.EncodingLength()+len(entryValue))
	pos := defn.TypeLogEntry.EncodeInto(ret)
	pos += length.EncodeInto(ret[pos:])
	copy(ret[pos:], entryValue)
	return ret
}

func hashLeaf(entryWire []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entryWire)
	return h.Sum(nil)
}

func treeHash(leafHashes [][]byte) []byte {
	switch len(leafHashes) {
	case 0:
		hash := sha256.Sum256(nil)
		return hash[:]
	case 1:
		return bytes.Clone(leafHashes[0])
	default:
		split := int(largestPowerOfTwoLessThan(uint64(len(leafHashes))))
		return nodeHash(treeHash(leafHashes[:split]), treeHash(leafHashes[split:]))
	}
}

func inclusionPath(leafHashes [][]byte, leafIndex uint64) [][]byte {
	if len(leafHashes) == 1 {
		return nil
	}

	split := largestPowerOfTwoLessThan(uint64(len(leafHashes)))
	if leafIndex < split {
		path := inclusionPath(leafHashes[:split], leafIndex)
		return append(path, treeHash(leafHashes[split:]))
	}

	path := inclusionPath(leafHashes[split:], leafIndex-split)
	return append(path, treeHash(leafHashes[:split]))
}

func rootFromInclusionPath(
	leafHash []byte,
	leafIndex uint64,
	treeSize uint64,
	siblingHashes [][]byte,
) ([]byte, error) {
	if treeSize == 1 {
		if len(siblingHashes) != 0 {
			return nil, fmt.Errorf("inclusion proof has %d unused sibling hashes", len(siblingHashes))
		}
		return bytes.Clone(leafHash), nil
	}
	if len(siblingHashes) == 0 {
		return nil, fmt.Errorf("inclusion proof is missing a sibling hash")
	}

	split := largestPowerOfTwoLessThan(treeSize)
	siblingHash := siblingHashes[len(siblingHashes)-1]
	remaining := siblingHashes[:len(siblingHashes)-1]
	if leafIndex < split {
		leftHash, err := rootFromInclusionPath(leafHash, leafIndex, split, remaining)
		if err != nil {
			return nil, err
		}
		return nodeHash(leftHash, siblingHash), nil
	}

	rightHash, err := rootFromInclusionPath(leafHash, leafIndex-split, treeSize-split, remaining)
	if err != nil {
		return nil, err
	}
	return nodeHash(siblingHash, rightHash), nil
}

func appendFrontier(frontier [][]byte, leafHash []byte) [][]byte {
	next := cloneHashes(frontier)
	carry := bytes.Clone(leafHash)
	for level := 0; ; level++ {
		if level == len(next) {
			next = append(next, carry)
			return next
		}
		if next[level] == nil {
			next[level] = carry
			return next
		}
		carry = nodeHash(next[level], carry)
		next[level] = nil
	}
}

func rootFromFrontier(frontier [][]byte) []byte {
	var root []byte
	for _, subtreeHash := range frontier {
		if subtreeHash == nil {
			continue
		}
		if root == nil {
			root = bytes.Clone(subtreeHash)
		} else {
			root = nodeHash(subtreeHash, root)
		}
	}
	if root == nil {
		hash := sha256.Sum256(nil)
		return hash[:]
	}
	return root
}

func largestPowerOfTwoLessThan(value uint64) uint64 {
	return uint64(1) << (bits.Len64(value-1) - 1)
}

func nodeHash(leftHash []byte, rightHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(leftHash)
	h.Write(rightHash)
	return h.Sum(nil)
}

func dataHashKey(dataHash []byte) [HashSize]byte {
	var key [HashSize]byte
	copy(key[:], dataHash)
	return key
}

func cloneHashes(hashes [][]byte) [][]byte {
	ret := make([][]byte, len(hashes))
	for i, hash := range hashes {
		ret[i] = bytes.Clone(hash)
	}
	return ret
}

func (t *Tree) storeState() StoreState {
	return StoreState{
		TreeSize:       t.Size(),
		RootHash:       rootFromFrontier(t.frontier),
		Frontier:       cloneHashes(t.frontier),
		LastIngestTime: t.lastIngestTime,
	}
}

func equalDataIndex(left map[[HashSize]byte]uint64, right map[[HashSize]byte]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for dataHash, leafIndex := range left {
		rightIndex, ok := right[dataHash]
		if !ok || rightIndex != leafIndex {
			return false
		}
	}
	return true
}
