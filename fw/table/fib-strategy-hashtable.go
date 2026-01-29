/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2022 Danning Yu.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

// This file implements a hash table version of the FIB, as outlined in section 2.3 of:
// W. So, A. Narayanan and D. Oran,
// "Named data networking on a router: Fast and DoS-resistant forwarding with hash tables,"
// Architectures for Networking and Communications Systems, 2013, pp. 215-225,
// doi: 10.1109/ANCS.2013.6665203.

package table

import (
	"sync"

	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
)

type virtualDetails struct {
	// md is the max depth associated with this virtual node, as defined in the paper.
	md int
}

// FibStrategyHashTable represents a tree implementation of the FIB-Strategy table.
type FibStrategyHashTable struct {
	// m is the name length for virtual nodes, as defined in the paper
	// Must be a positive value
	m int

	// realTable is a map of names (hashed as uint64 values) to the FIB entry
	// associated with that name.
	realTable map[uint64]*baseFibStrategyEntry

	// virtTable is a map of virtual names (hashed as uint64 values) to the
	// virtualDetails struct associated with that virtual name.
	virtTable map[uint64]*virtualDetails

	// virtTableNames is a map of virtual names (hashed as uint64 values) to
	// a set of all the real names associated with that virtual name. The
	// inner map is being used as a set to map name bytes into lengths.
	// string is simply used as an immutable version of bytes
	virtTableNames map[uint64](map[string]int)

	// fibStrategyRWMutex is a mutex used to synchronize accesses to the FIB,
	// which is shared across all the forwarding threads.
	fibStrategyRWMutex sync.RWMutex
}

// newFibStrategyTableHashTable creates a new FIB with the hash table algorithm.
// The argument m determines the virtual name length.
func newFibStrategyTableHashTable(m uint16) {
	FibStrategyTable = new(FibStrategyHashTable)
	fibStrategyTableHashTable := FibStrategyTable.(*FibStrategyHashTable)

	fibStrategyTableHashTable.m = int(m) // Cast to int so that it's easy to pass to name.Prefix
	fibStrategyTableHashTable.realTable = make(map[uint64]*baseFibStrategyEntry)
	fibStrategyTableHashTable.virtTable = make(map[uint64]*virtualDetails)
	fibStrategyTableHashTable.virtTableNames = make(map[uint64]map[string]int)

	rtEntry := new(baseFibStrategyEntry)
	rtEntry.name = enc.Name{}
	rtEntry.strategy = defn.DEFAULT_STRATEGY
	fibStrategyTableHashTable.realTable[enc.Name{}.Hash()] = rtEntry
}

// findLongestPrefixMatch returns the entry corresponding to the longest
// prefix match of the given name. It returns nil if no exact match was found.
func (f *FibStrategyHashTable) findLongestPrefixMatchEnc(name enc.Name) *baseFibStrategyEntry {
	prefixHash := name.PrefixHash()
	if len(name) <= f.m {
		// Name length is less than or equal to M, so only need to check real table
		for pfx := len(name); pfx >= 0; pfx-- {
			if val, ok := f.realTable[prefixHash[pfx]]; ok {
				return val
			}
		}
		return nil
	}

	// Name is longer than M, so use virtual node to lookup first
	// virtName := (name)[:f.m]
	virtNameHash := prefixHash[f.m]
	virtEntry, ok := f.virtTable[virtNameHash]
	if ok {
		// Virtual name present, look for longer matches
		pfx := min(virtEntry.md, len(name))
		for ; pfx > f.m; pfx-- {
			if val, ok := f.realTable[prefixHash[pfx]]; ok {
				return val
			}
		}
	}

	// Name is longer that M but did not find a match for names with length > M
	// Start looking in the real table from length M
	// For example: Table has prefixes /a and /a/b/c, virtual entry is /a/b
	// A search for /a/b/d will not match /a/b/c, so we need it to match /a
	for pfx := f.m; pfx >= 0; pfx-- {
		if val, ok := f.realTable[prefixHash[pfx]]; ok {
			return val
		}
	}

	// no match found
	return nil
}

// insertEntry inserts an entry into the FIB table, specifically realTable,
// virtTable, and virtTableNames. It does not set the nexthops or strategy
// fields of the newly created entry. The caller is responsible for doing that.
func (f *FibStrategyHashTable) insertEntryEnc(name enc.Name) *baseFibStrategyEntry {
	prefixHash := name.PrefixHash()
	nameHash := prefixHash[len(name)]
	nameBytes := string(name.Bytes())

	if _, ok := f.realTable[nameHash]; !ok {
		rtEntry := new(baseFibStrategyEntry)
		rtEntry.name = name
		f.realTable[nameHash] = rtEntry
	}

	// Insert into virtual table if name size >= M
	if len(name) == f.m {
		if _, ok := f.virtTable[nameHash]; !ok {
			vtEntry := new(virtualDetails)
			vtEntry.md = len(name)
			f.virtTable[nameHash] = vtEntry
		}

		if _, ok := f.virtTableNames[nameHash]; !ok {
			f.virtTableNames[nameHash] = make(map[string]int)
		}

		f.virtTable[nameHash].md = max(f.virtTable[nameHash].md, len(name))

		// Insert into set of names
		f.virtTableNames[nameHash][nameBytes] = len(name)

	} else if len(name) > f.m {
		virtNameHash := prefixHash[f.m]
		if _, ok := f.virtTable[virtNameHash]; !ok {
			vtEntry := new(virtualDetails)
			vtEntry.md = len(name)
			f.virtTable[virtNameHash] = vtEntry
		}

		if _, ok := f.virtTableNames[virtNameHash]; !ok {
			f.virtTableNames[virtNameHash] = make(map[string]int)
		}

		f.virtTable[virtNameHash].md = max(f.virtTable[virtNameHash].md, len(name))

		// Insert into set of names
		f.virtTableNames[virtNameHash][nameBytes] = len(name)
	}

	return f.realTable[nameHash]
}

// pruneTables takes in an entry and removes it from the real table if it has no
// next hops and no strategy associated with it. It also eliminates its
// corresponding virtual entry, if applicable.
func (f *FibStrategyHashTable) pruneTables(entry *baseFibStrategyEntry) {
	var pruned bool
	name := entry.name
	prefixHash := name.PrefixHash()
	nameHash := prefixHash[len(name)]
	nameBytes := string(name.Bytes())

	// Delete the real entry
	if len(entry.nexthops) == 0 && entry.strategy == nil {
		delete(f.realTable, nameHash)
		pruned = true
	}

	if !pruned {
		return
	}

	// Delete the virtual entry too, if needed
	if len(name) >= f.m {
		virtNameHash := prefixHash[f.m]
		virtEntry, inVirtTable := f.virtTable[virtNameHash]
		virtTableNamesEntry, inVirtNameTable := f.virtTableNames[virtNameHash]
		namePresentForVirtName := false
		if inVirtNameTable {
			_, namePresentForVirtName = virtTableNamesEntry[nameBytes]
		}

		// If virtual name is present in table
		// AND real name is associated with this virtual name
		// AND this real name was deleted from the real table
		// Then delete from virtualTableNames if it's last real name
		// associated with the virtual name
		if inVirtTable && namePresentForVirtName && pruned {
			delete(virtTableNamesEntry, nameBytes)
			if len(virtTableNamesEntry) == 0 {
				delete(f.virtTableNames, virtNameHash)
			}
		}

		// If virtual name is present in table
		// AND the real name being deleted was the longest associated with the virtual name
		// AND this real name was deleted from the real table
		if inVirtTable && len(name) == virtEntry.md && pruned {
			_, inVirtNameTable = f.virtTableNames[virtNameHash]
			if !inVirtNameTable {
				// Delete the entry entirely from the virtual table too
				// if it was removed it from the virtual name table
				delete(f.virtTable, virtNameHash)
			} else {
				// Update with length of next longest real prefix associated
				// with this virtual prefix
				for _, l := range f.virtTableNames[virtNameHash] {
					virtEntry.md = max(virtEntry.md, l)
				}
			}
		}
	}
}

// FindNextHops returns the longest-prefix matching nexthop(s) matching the specified name.

// (AI GENERATED DESCRIPTION): FindNextHopsEnc returns the list of next‑hop entries for the longest prefix match of the supplied name, scanning from that prefix downwards until it finds an entry with nexthops, or nil if no such entry exists.
func (f *FibStrategyHashTable) FindNextHopsEnc(name enc.Name) []*FibNextHopEntry {
	f.fibStrategyRWMutex.RLock()
	defer f.fibStrategyRWMutex.RUnlock()

	entry := f.findLongestPrefixMatchEnc(name)

	if entry == nil {
		return nil
	}

	// Go backwards to find the first entry with nexthops
	// since some might only have a strategy but no nexthops
	prefixHash := name.PrefixHash()
	for pfx := len(entry.name); pfx >= 0; pfx-- {
		val, ok := f.realTable[prefixHash[pfx]]
		if ok && len(val.nexthops) > 0 {
			return val.nexthops
		}
	}

	return nil
}

// FindStrategy returns the longest-prefix matching strategy choice entry for the specified name.

// (AI GENERATED DESCRIPTION): Finds and returns the strategy name for the longest‑matching prefix of a given name, searching ancestor prefixes in the FIB until a strategy is found or nil is returned if none exists.
func (f *FibStrategyHashTable) FindStrategyEnc(name enc.Name) enc.Name {
	f.fibStrategyRWMutex.RLock()
	defer f.fibStrategyRWMutex.RUnlock()

	entry := f.findLongestPrefixMatchEnc(name)

	if entry == nil {
		return nil
	}

	// Go backwards to find the first entry with strategy
	// since some might only have a nexthops but no strategy
	prefixHash := name.PrefixHash()
	for pfx := len(entry.name); pfx >= 0; pfx-- {
		val, ok := f.realTable[prefixHash[pfx]]
		if ok && val.strategy != nil {
			return val.strategy
		}
	}

	return nil
}

// InsertNextHop adds or updates a nexthop entry for the specified prefix.
func (f *FibStrategyHashTable) InsertNextHopEnc(name enc.Name, nexthop uint64, cost uint64) {
	f.fibStrategyRWMutex.Lock()
	defer f.fibStrategyRWMutex.Unlock()

	realEntry := f.insertEntryEnc(name)

	for _, existingNextHop := range realEntry.nexthops {
		if existingNextHop.Nexthop == nexthop {
			// Update existing hop
			existingNextHop.Cost = cost
			return
		}
	}

	// Did not update existing hop, so add a new hop
	nhEntry := new(FibNextHopEntry)
	nhEntry.Nexthop = nexthop
	nhEntry.Cost = cost
	realEntry.nexthops = append(realEntry.nexthops, nhEntry)

}

// ClearNextHops clears all nexthops for the specified prefix.
func (f *FibStrategyHashTable) ClearNextHopsEnc(name enc.Name) {
	f.fibStrategyRWMutex.Lock()
	defer f.fibStrategyRWMutex.Unlock()

	entry, ok := f.realTable[name.Hash()]
	if ok {
		entry.nexthops = make([]*FibNextHopEntry, 0)
		f.pruneTables(entry)
	}
}

// RemoveNextHop removes the specified nexthop entry from the specified prefix

// (AI GENERATED DESCRIPTION): Removes the specified next hop from the FIB entry corresponding to the given encoded name, updating internal tables and pruning any empty entries.
func (f *FibStrategyHashTable) RemoveNextHopEnc(name enc.Name, nexthop uint64) {
	f.fibStrategyRWMutex.Lock()
	defer f.fibStrategyRWMutex.Unlock()

	nameHash := name.Hash()
	if _, ok := f.realTable[nameHash]; !ok {
		return
	}

	// Remove matching nexthop from real table (if one exists)
	realEntry := f.realTable[nameHash]
	nextHops := realEntry.nexthops
	for i, nh := range nextHops {
		if nh.Nexthop == nexthop {
			if len(nextHops) > 1 {
				nextHops[i] = nextHops[len(nextHops)-1]
			}
			realEntry.nexthops = nextHops[:len(nextHops)-1]
			f.pruneTables(realEntry)
			break
		}
	}
}

// GetNumFIBEntries returns the number of entries in the FIB.
func (f *FibStrategyHashTable) GetNumFIBEntries() int {
	f.fibStrategyRWMutex.RLock()
	defer f.fibStrategyRWMutex.RUnlock()

	return len(f.realTable)
}

// GetAllFIBEntries returns all nexthop entries in the FIB.
func (f *FibStrategyHashTable) GetAllFIBEntries() []FibStrategyEntry {
	f.fibStrategyRWMutex.RLock()
	defer f.fibStrategyRWMutex.RUnlock()

	entries := make([]FibStrategyEntry, 0)
	for _, v := range f.realTable {
		if len(v.nexthops) > 0 {
			entries = append(entries, v)
		}
	}

	return entries
}

// SetStrategy sets the strategy for the specified prefix.

// (AI GENERATED DESCRIPTION): Sets the routing strategy for a given name entry in the FIB strategy hash table, ensuring thread‑safe update of the entry’s strategy field.
func (f *FibStrategyHashTable) SetStrategyEnc(name enc.Name, strategy enc.Name) {
	f.fibStrategyRWMutex.Lock()
	defer f.fibStrategyRWMutex.Unlock()

	realEntry := f.insertEntryEnc(name)
	realEntry.strategy = strategy
}

// UnsetStrategy unsets the strategy for the specified prefix.
func (f *FibStrategyHashTable) UnSetStrategyEnc(name enc.Name) {
	f.fibStrategyRWMutex.Lock()
	defer f.fibStrategyRWMutex.Unlock()

	entry, ok := f.realTable[name.Hash()]
	if ok {
		entry.strategy = nil
		f.pruneTables(entry)
	}
}

// GetAllForwardingStrategies returns all strategy choice entries in the Strategy Table.
func (f *FibStrategyHashTable) GetAllForwardingStrategies() []FibStrategyEntry {
	f.fibStrategyRWMutex.RLock()
	defer f.fibStrategyRWMutex.RUnlock()
	entries := make([]FibStrategyEntry, 0)
	for _, v := range f.realTable {
		if v.strategy != nil {
			entries = append(entries, v)
		}
	}

	return entries
}
