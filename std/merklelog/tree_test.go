package merklelog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
	"github.com/stretchr/testify/require"
)

func TestTreeRootVectors(t *testing.T) {
	expectedRoots := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"3e49ed62039635b1f465bb6feb941b748a037f7461d1e29728db61011e51aebf",
		"e9405c348553e9feb5a6234d6e91598090b7b16c5979110f2290f1d010a8114f",
		"0ebbdd04404e790bcd16c3ac9265bdd68ab9aa577c67590b25c0c6b2f545acf0",
		"fbb2aa61e73070546d195d57e57ed1cf3a9c1073e86afd129f41367a06dc0ff1",
		"38ad2533c3b04b36c0f9c776011a2aea486d75edb710c8981f0a17f168a5262a",
		"faec623ba14e1fe04b2c556578ab74756573c5db0824b6a05b67ad2532da50e3",
		"1d80070a35eaa80d58c83c4f3b5a2c367c61f2233cafa40791bd8d856d9ccc0c",
		"c80e2f1be2197852e733b9b0a6eb6d475e7d66871c95f4d67c20437ca04753b7",
	}

	tree := NewTree()
	for size, expectedRoot := range expectedRoots {
		root := tree.Root()
		require.Equal(t, uint64(size), root.TreeSize)
		require.Equal(t, expectedRoot, hex.EncodeToString(root.RootHash))

		if size < len(expectedRoots)-1 {
			leafIndex, err := tree.Append(testEntryWire(size))
			require.NoError(t, err)
			require.Equal(t, uint64(size), leafIndex)
		}
	}
}

func TestLogEntryAndLeafHashVectors(t *testing.T) {
	entryWire := testEntryWire(0)
	require.Equal(t,
		"fd1e122afd1e160203e8fd1e0020e501858e369df59267c5d1e0d0591806880984af98708c9406efca8055647634",
		hex.EncodeToString(entryWire),
	)

	entry, err := ParseLogEntry(entryWire)
	require.NoError(t, err)
	require.Equal(t, testEntry(0), entry)

	leafHash, err := LeafHash(entryWire)
	require.NoError(t, err)
	require.Equal(t,
		"3e49ed62039635b1f465bb6feb941b748a037f7461d1e29728db61011e51aebf",
		hex.EncodeToString(leafHash),
	)
}

func TestInclusionProofs(t *testing.T) {
	for size := 1; size <= 16; size++ {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			tree := NewTree()
			entries := make([]*defn.LogEntry, size)
			for i := range entries {
				entries[i] = testEntry(i)
				_, err := tree.Append(mustEncodeLogEntry(entries[i]))
				require.NoError(t, err)
			}

			root := tree.Root()
			for leafIndex, entry := range entries {
				proof, err := tree.InclusionProof(uint64(leafIndex))
				require.NoError(t, err)
				require.NoError(t, VerifyInclusion(entry.DataHashes[0], proof, root))
				parsedEntry, err := ParseProofEntry(proof)
				require.NoError(t, err)
				require.Equal(t, entry, parsedEntry)
			}
		})
	}
}

func TestInclusionProofEncodingPreservesEntryWire(t *testing.T) {
	tree := NewTree()
	entryWire := testEntryWire(0)
	_, err := tree.Append(entryWire)
	require.NoError(t, err)
	proof, err := tree.InclusionProof(0)
	require.NoError(t, err)

	parsed, err := defn.ParseInclusionProof(enc.NewWireView(proof.Encode()), false)
	require.NoError(t, err)
	require.Equal(t, entryWire, wrapLogEntryValue(parsed.Entry.Join()))
	require.NoError(t, VerifyInclusion(testDataHash(0), parsed, tree.Root()))
}

func TestVerifyInclusionRejectsMutations(t *testing.T) {
	tree := NewTree()
	entries := make([]*defn.LogEntry, 5)
	for i := range entries {
		entries[i] = testEntry(i)
		entries[i].DataHashes = append(entries[i].DataHashes, testDataHash(i+100))
		_, err := tree.Append(mustEncodeLogEntry(entries[i]))
		require.NoError(t, err)
	}

	dataHash := entries[4].DataHashes[0]
	proof, err := tree.InclusionProof(4)
	require.NoError(t, err)
	root := tree.Root()
	require.NoError(t, VerifyInclusion(dataHash, proof, root))

	t.Run("requested hash", func(t *testing.T) {
		mutated := bytes.Clone(dataHash)
		mutated[0] ^= 0xff
		require.Error(t, VerifyInclusion(mutated, proof, root))
	})

	t.Run("entry hash", func(t *testing.T) {
		mutated := cloneProof(proof)
		entry := mustParseProofEntry(mutated)
		entry.DataHashes[1][0] ^= 0xff
		setProofEntry(mutated, entry)
		require.Error(t, VerifyInclusion(dataHash, mutated, root))
	})

	t.Run("ingestion time", func(t *testing.T) {
		mutated := cloneProof(proof)
		entry := mustParseProofEntry(mutated)
		entry.IngestTime += time.Millisecond
		setProofEntry(mutated, entry)
		require.Error(t, VerifyInclusion(dataHash, mutated, root))
	})

	t.Run("sibling hash", func(t *testing.T) {
		mutated := cloneProof(proof)
		mutated.SiblingHashes[0][0] ^= 0xff
		require.Error(t, VerifyInclusion(dataHash, mutated, root))
	})

	t.Run("leaf index", func(t *testing.T) {
		mutated := cloneProof(proof)
		mutated.LeafIndex--
		require.Error(t, VerifyInclusion(dataHash, mutated, root))
	})

	t.Run("tree size", func(t *testing.T) {
		mutated := cloneRoot(root)
		mutated.TreeSize++
		require.Error(t, VerifyInclusion(dataHash, proof, mutated))
	})

	t.Run("root hash", func(t *testing.T) {
		mutated := cloneRoot(root)
		mutated.RootHash[0] ^= 0xff
		require.Error(t, VerifyInclusion(dataHash, proof, mutated))
	})

	t.Run("missing sibling", func(t *testing.T) {
		mutated := cloneProof(proof)
		mutated.SiblingHashes = mutated.SiblingHashes[1:]
		require.Error(t, VerifyInclusion(dataHash, mutated, root))
	})

	t.Run("extra sibling", func(t *testing.T) {
		mutated := cloneProof(proof)
		mutated.SiblingHashes = append(mutated.SiblingHashes, make([]byte, HashSize))
		require.Error(t, VerifyInclusion(dataHash, mutated, root))
	})
}

func TestTreeCopiesCallerData(t *testing.T) {
	tree := NewTree()
	entryWire := testEntryWire(0)
	originalWire := bytes.Clone(entryWire)
	_, err := tree.Append(entryWire)
	require.NoError(t, err)

	expectedRoot := tree.Root()
	entryWire[len(entryWire)-1] ^= 0xff
	require.Equal(t, expectedRoot, tree.Root())

	proof, err := tree.InclusionProof(0)
	require.NoError(t, err)
	proof.Entry[0][0] ^= 0xff

	freshProof, err := tree.InclusionProof(0)
	require.NoError(t, err)
	require.Equal(t, originalWire, wrapLogEntryValue(freshProof.Entry.Join()))
	require.NoError(t, VerifyInclusion(testDataHash(0), freshProof, tree.Root()))

	root := tree.Root()
	root.RootHash[0] ^= 0xff
	require.Equal(t, expectedRoot, tree.Root())
}

func TestTreeRejectsInvalidInputs(t *testing.T) {
	invalidEntries := map[string]*defn.LogEntry{
		"nil":                  nil,
		"negative time":        {IngestTime: -time.Millisecond, DataHashes: [][]byte{testDataHash(0)}},
		"sub-millisecond time": {IngestTime: time.Nanosecond, DataHashes: [][]byte{testDataHash(0)}},
		"no hashes":            {IngestTime: time.Second},
		"short hash":           {IngestTime: time.Second, DataHashes: [][]byte{{0x01}}},
	}
	for name, entry := range invalidEntries {
		t.Run(name, func(t *testing.T) {
			_, err := EncodeLogEntry(entry)
			require.Error(t, err)
		})
	}

	validWire := testEntryWire(0)
	invalidWires := map[string][]byte{
		"nil":           nil,
		"wrong type":    append([]byte{0x01}, validWire[3:]...),
		"wrong length":  append(bytes.Clone(validWire[:3]), append([]byte{0x01}, validWire[4:]...)...),
		"truncated":     validWire[:len(validWire)-1],
		"non-canonical": append([]byte{0xfd, 0x1e, 0x12, 0xfd, 0x00, validWire[3]}, validWire[4:]...),
	}
	for name, entryWire := range invalidWires {
		t.Run(name, func(t *testing.T) {
			tree := NewTree()
			_, err := tree.Append(entryWire)
			require.Error(t, err)
			require.Zero(t, tree.Size())
		})
	}

	tree := NewTree()
	_, err := tree.Append(validWire)
	require.NoError(t, err)
	_, err = tree.InclusionProof(1)
	require.Error(t, err)
}

func TestTreeRejectsDuplicateHashesAndNonIncreasingTime(t *testing.T) {
	tree := NewTree()
	_, err := tree.Append(testEntryWire(0))
	require.NoError(t, err)

	duplicate := testEntry(1)
	duplicate.DataHashes[0] = testDataHash(0)
	_, err = tree.Append(mustEncodeLogEntry(duplicate))
	require.ErrorIs(t, err, ErrDuplicateDataHash)

	withinEntry := testEntry(1)
	withinEntry.DataHashes = append(withinEntry.DataHashes, withinEntry.DataHashes[0])
	_, err = tree.Append(mustEncodeLogEntry(withinEntry))
	require.ErrorIs(t, err, ErrDuplicateDataHash)

	nonIncreasing := testEntry(1)
	nonIncreasing.IngestTime = testEntry(0).IngestTime
	_, err = tree.Append(mustEncodeLogEntry(nonIncreasing))
	require.Error(t, err)
	require.Equal(t, uint64(1), tree.Size())
}

func TestVerifyInclusionRejectsMalformedProofs(t *testing.T) {
	tree := NewTree()
	entry := testEntry(0)
	_, err := tree.Append(mustEncodeLogEntry(entry))
	require.NoError(t, err)
	proof, err := tree.InclusionProof(0)
	require.NoError(t, err)
	root := tree.Root()

	tests := map[string]func() ([]byte, *defn.InclusionProof, *defn.TreeRoot){
		"short requested hash": func() ([]byte, *defn.InclusionProof, *defn.TreeRoot) {
			return []byte{0x01}, proof, root
		},
		"nil proof": func() ([]byte, *defn.InclusionProof, *defn.TreeRoot) {
			return entry.DataHashes[0], nil, root
		},
		"nil root": func() ([]byte, *defn.InclusionProof, *defn.TreeRoot) {
			return entry.DataHashes[0], proof, nil
		},
		"empty tree": func() ([]byte, *defn.InclusionProof, *defn.TreeRoot) {
			return entry.DataHashes[0], proof, NewTree().Root()
		},
		"short root hash": func() ([]byte, *defn.InclusionProof, *defn.TreeRoot) {
			return entry.DataHashes[0], proof, &defn.TreeRoot{TreeSize: 1, RootHash: []byte{0x01}}
		},
		"nil entry": func() ([]byte, *defn.InclusionProof, *defn.TreeRoot) {
			mutated := cloneProof(proof)
			mutated.Entry = nil
			return entry.DataHashes[0], mutated, root
		},
		"short sibling hash": func() ([]byte, *defn.InclusionProof, *defn.TreeRoot) {
			mutated := cloneProof(proof)
			mutated.SiblingHashes = [][]byte{{0x01}}
			return entry.DataHashes[0], mutated, root
		},
	}

	for name, makeInput := range tests {
		t.Run(name, func(t *testing.T) {
			dataHash, proof, root := makeInput()
			require.Error(t, VerifyInclusion(dataHash, proof, root))
		})
	}
}

func testEntry(index int) *defn.LogEntry {
	return &defn.LogEntry{
		IngestTime: time.Duration(1000+index) * time.Millisecond,
		DataHashes: [][]byte{testDataHash(index)},
	}
}

func testEntryWire(index int) []byte {
	return mustEncodeLogEntry(testEntry(index))
}

func testDataHash(index int) []byte {
	hash := sha256.Sum256([]byte("data-" + strconv.Itoa(index)))
	return hash[:]
}

func mustEncodeLogEntry(entry *defn.LogEntry) []byte {
	wire, err := EncodeLogEntry(entry)
	if err != nil {
		panic(err)
	}
	return wire
}

func mustParseProofEntry(proof *defn.InclusionProof) *defn.LogEntry {
	entry, err := ParseProofEntry(proof)
	if err != nil {
		panic(err)
	}
	return entry
}

func setProofEntry(proof *defn.InclusionProof, entry *defn.LogEntry) {
	entryWire := mustEncodeLogEntry(entry)
	_, entryValue, err := decodeLogEntry(entryWire)
	if err != nil {
		panic(err)
	}
	proof.Entry = enc.Wire{entryValue}
}

func cloneProof(proof *defn.InclusionProof) *defn.InclusionProof {
	return &defn.InclusionProof{
		Entry:         enc.Wire{bytes.Clone(proof.Entry.Join())},
		LeafIndex:     proof.LeafIndex,
		SiblingHashes: cloneHashes(proof.SiblingHashes),
	}
}

func cloneRoot(root *defn.TreeRoot) *defn.TreeRoot {
	return &defn.TreeRoot{
		TreeSize: root.TreeSize,
		RootHash: bytes.Clone(root.RootHash),
	}
}
