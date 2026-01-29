package sync

import (
	"cmp"
	"iter"
	"slices"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
)

// Map representation of the state vector.
type SvMap[V any] map[string][]SvMapVal[V]

// One entry in the state vector map.
type SvMapVal[V any] struct {
	Boot  uint64
	Value V
}

// (AI GENERATED DESCRIPTION): Compares the Boot field of two SvMapVal[V] values, returning a negative, zero, or positive integer to indicate their ordering.
func (*SvMapVal[V]) Cmp(a, b SvMapVal[V]) int {
	return cmp.Compare(a.Boot, b.Boot)
}

// Create a new state vector map.
func NewSvMap[V any](size int) SvMap[V] {
	return make(SvMap[V], size)
}

// Get seq entry for a bootstrap time.
func (m SvMap[V]) Get(hash string, boot uint64) (value V) {
	entry := SvMapVal[V]{boot, value}
	i, match := slices.BinarySearchFunc(m[hash], entry, entry.Cmp)
	if match {
		return m[hash][i].Value
	}
	return value
}

// (AI GENERATED DESCRIPTION): Adds or updates a value in the sorted list for a given hash, inserting the new entry or replacing the existing one while maintaining the slice sorted by the boot field.
func (m SvMap[V]) Set(hash string, boot uint64, value V) {
	entry := SvMapVal[V]{boot, value}
	i, match := slices.BinarySearchFunc(m[hash], entry, entry.Cmp)
	if match {
		m[hash][i] = entry
		return
	}
	m[hash] = slices.Insert(m[hash], i, entry)
}

// (AI GENERATED DESCRIPTION): Clears all key/value pairs from the SvMap, safely handling nil maps by doing nothing if the map is nil.
func (m SvMap[V]) Clear() {
	if m != nil {
		clear(m)
	}
}

// Check if a SvMap is newer than another.
// cmp(a, b) is the function to compare values (a > b).
func (m SvMap[V]) IsNewerThan(other SvMap[V], cmp func(V, V) bool) bool {
	// TODO: optimize with two pointers
	for hash, entries := range m {
		for _, entry := range entries {
			foundOther := false
			for _, otherEntry := range other[hash] {
				if otherEntry.Boot == entry.Boot {
					foundOther = true
					if cmp(entry.Value, otherEntry.Value) {
						return true
					}
				}
			}
			if !foundOther {
				return true
			}
		}
	}
	return false
}

// Encode the state vector map to a StateVector.
// seq is the function to get the sequence number
func (m SvMap[V]) Encode(seq func(V) uint64) *spec_svs.StateVector {
	entries := make([]*spec_svs.StateVectorEntry, 0, len(m))

	// Pre-allocate the slice for sequence entries
	numSeqEntries := 0
	for _, entries := range m {
		numSeqEntries += len(entries)
	}
	seqNoEntries := make([]*spec_svs.SeqNoEntry, numSeqEntries)

	for name, vals := range m.Iter() {
		entry := &spec_svs.StateVectorEntry{
			Name:         name,
			SeqNoEntries: seqNoEntries[:0],
		}
		entries = append(entries, entry)
		seqNoEntries = seqNoEntries[len(vals):]

		for _, val := range vals {
			if seqNo := seq(val.Value); seqNo > 0 {
				entry.SeqNoEntries = append(entry.SeqNoEntries, &spec_svs.SeqNoEntry{
					BootstrapTime: val.Boot,
					SeqNo:         seqNo,
				})
			}
		}
	}

	// Sort entries by in the NDN canonical order
	slices.SortFunc(entries, func(a, b *spec_svs.StateVectorEntry) int {
		return a.Name.Compare(b.Name)
	})

	return &spec_svs.StateVector{Entries: entries}
}

// (AI GENERATED DESCRIPTION): Iter returns an iterator over the SvMap that yields each decoded name and its associated slice of SvMapVal values.
func (m SvMap[V]) Iter() iter.Seq2[enc.Name, []SvMapVal[V]] {
	return func(yield func(enc.Name, []SvMapVal[V]) bool) {
		for hash, val := range m {
			name, err := enc.NameFromTlvStr(hash)
			if err != nil {
				log.Error(nil, "[BUG] invalid name in SvMap", "hash", hash)
				continue
			}
			if !yield(name, val) {
				return
			}
		}
	}
}
