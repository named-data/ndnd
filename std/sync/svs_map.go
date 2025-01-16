package sync

import (
	"sort"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
)

// Map representation of the state vector.
type SvMap map[string][]spec_svs.SeqNoEntry

// Create a new state vector map.
func NewSvMap(size int) SvMap {
	return make(SvMap, size)
}

// Get seq entry for a bootstrap time.
func (m SvMap) Get(hash string, btime uint64) spec_svs.SeqNoEntry {
	for _, entry := range m[hash] {
		if entry.BootstrapTime == btime {
			return entry
		}
	}
	return spec_svs.SeqNoEntry{
		BootstrapTime: btime,
		SeqNo:         0,
	}
}

// Set seq entry for a bootstrap time.
func (m SvMap) Set(hash string, btime uint64, seq uint64) {
	for i, entry := range m[hash] {
		if entry.BootstrapTime == btime {
			m[hash][i].SeqNo = seq
			return
		}
	}
	m[hash] = append(m[hash], spec_svs.SeqNoEntry{
		BootstrapTime: btime,
		SeqNo:         seq,
	})
	sort.Slice(m[hash], func(i, j int) bool {
		return m[hash][i].BootstrapTime < m[hash][j].BootstrapTime
	})
}

// Check if a svHashMap is newer than another.
// If existOnly is true, only check if the other has all entries.
func (m SvMap) IsNewerThan(other SvMap, existOnly bool) bool {
	for hash, entries := range m {
		for _, entry := range entries {
			foundOther := false
			for _, otherEntry := range other[hash] {
				if otherEntry.BootstrapTime == entry.BootstrapTime {
					foundOther = true
					if !existOnly && otherEntry.SeqNo < entry.SeqNo {
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

func (m SvMap) Encode() *spec_svs.StateVector {
	entries := make([]*spec_svs.StateVectorEntry, 0, len(m))
	for hash, seqEntrs := range m {
		seqEntrPtrs := make([]*spec_svs.SeqNoEntry, 0, len(seqEntrs))
		for _, e := range seqEntrs {
			if e.SeqNo > 0 {
				seqEntrPtrs = append(seqEntrPtrs, &e)
			}
		}

		name, err := enc.NameFromStr(hash)
		if err != nil {
			log.Error(nil, "Invalid name in SV map", "hash", hash)
			continue
		}

		entries = append(entries, &spec_svs.StateVectorEntry{
			Name:         name,
			SeqNoEntries: seqEntrPtrs,
		})
	}

	// Sort entries by in the NDN canonical order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name.Compare(entries[j].Name) < 0
	})

	return &spec_svs.StateVector{Entries: entries}
}
