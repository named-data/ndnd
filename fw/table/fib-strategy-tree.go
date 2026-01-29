/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"container/list"
	"sync"

	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
)

type fibStrategyTreeEntry struct {
	baseFibStrategyEntry
	depth    int
	parent   *fibStrategyTreeEntry
	children []*fibStrategyTreeEntry
}

// FibStrategy Tree represents a tree implementation of the FIB-Strategy table.
type FibStrategyTree struct {
	// root of the tree
	root *fibStrategyTreeEntry

	// mutex used to synchronize accesses to the FIB,
	// which is shared across all the forwarding threads.
	mutex sync.RWMutex
}

// (AI GENERATED DESCRIPTION): Initializes the FibStrategyTable with a new FibStrategyTree whose root entry has an empty component, default strategy, and empty name.
func newFibStrategyTableTree() {
	FibStrategyTable = new(FibStrategyTree)
	tree := FibStrategyTable.(*FibStrategyTree)

	// Root component will be empty
	tree.root = new(fibStrategyTreeEntry)
	tree.root.component = enc.Component{}
	tree.root.strategy = defn.DEFAULT_STRATEGY
	tree.root.name = enc.Name{}
}

// findExactMatchEntry returns the entry corresponding to the exact match of
// the given name. It returns nil if no exact match was found.
func (f *fibStrategyTreeEntry) findExactMatchEntryEnc(name enc.Name) *fibStrategyTreeEntry {
	match := f.findLongestPrefixEntryEnc(name)
	if len(name) == len(match.name) {
		return match
	}
	return nil
}

// findLongestPrefixEntry returns the entry corresponding to the longest
// prefix match of the given name. It returns nil if no exact match was found.
func (f *fibStrategyTreeEntry) findLongestPrefixEntryEnc(name enc.Name) *fibStrategyTreeEntry {
	if len(name) > f.depth {
		for _, child := range f.children {
			if At(name, child.depth-1).Equal(child.component) {
				return child.findLongestPrefixEntryEnc(name)
			}
		}
	}
	return f
}

// fillTreeToPrefix breaks the given name into components and adds nodes to the
// tree for any missing components.
func (f *FibStrategyTree) fillTreeToPrefixEnc(name enc.Name) *fibStrategyTreeEntry {
	entry := f.root.findLongestPrefixEntryEnc(name)

	for depth := entry.depth; depth < len(name); depth++ {
		component := At(name, depth).Clone()

		child := &fibStrategyTreeEntry{}
		child.name = entry.name.Append(component)
		child.depth = depth + 1
		child.component = component
		child.parent = entry
		child.children = make([]*fibStrategyTreeEntry, 0)

		entry.children = append(entry.children, child)
		entry = child
	}
	return entry
}

// pruneIfEmpty prunes nodes from the tree if they no longer carry any information,
// where information is the combination of child nodes, nexthops, and strategies.
func (f *fibStrategyTreeEntry) pruneIfEmpty() {
	for entry := f; entry.parent != nil && len(entry.children) == 0 && len(entry.nexthops) == 0 && entry.strategy == nil; entry = entry.parent {
		// Remove from parent's children
		for i, child := range entry.parent.children {
			if child == f {
				if i < len(entry.parent.children)-1 {
					copy(entry.parent.children[i:], entry.parent.children[i+1:])
				}
				entry.parent.children = entry.parent.children[:len(entry.parent.children)-1]
				break
			}
		}
	}
}

// FindNextHops returns the longest-prefix matching nexthop(s) matching the specified name.
func (f *FibStrategyTree) FindNextHopsEnc(name enc.Name) []*FibNextHopEntry {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	// Find longest prefix matching entry
	entry := f.root.findLongestPrefixEntryEnc(name)

	// Now step back up until we find a nexthops entry
	// since some might only have a strategy but no nexthops
	for ; entry != nil; entry = entry.parent {
		if len(entry.nexthops) > 0 {
			return append([]*FibNextHopEntry{}, entry.nexthops...)
		}
	}

	return []*FibNextHopEntry{}
}

// FindStrategy returns the longest-prefix matching strategy choice entry for the specified name.
func (f *FibStrategyTree) FindStrategyEnc(name enc.Name) enc.Name {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	// Find longest prefix matching entry
	entry := f.root.findLongestPrefixEntryEnc(name)

	// Now step back up until we find a strategy entry
	// since some might only have a nexthops but no strategy
	var strategy enc.Name
	for ; entry != nil; entry = entry.parent {
		if entry.strategy != nil {
			strategy = entry.strategy
			break
		}
	}

	return strategy
}

// InsertNextHop adds or updates a nexthop entry for the specified prefix.
func (f *FibStrategyTree) InsertNextHopEnc(name enc.Name, nexthop uint64, cost uint64) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	entry := f.fillTreeToPrefixEnc(name)

	// Update existing nexthop entry if it exists
	for _, nh := range entry.nexthops {
		if nh.Nexthop == nexthop {
			nh.Cost = cost
			return
		}
	}

	// Add new nexthop entry
	entry.nexthops = append(entry.nexthops, &FibNextHopEntry{
		Nexthop: nexthop,
		Cost:    cost,
	})
}

// ClearNextHops clears all nexthops for the specified prefix.
func (f *FibStrategyTree) ClearNextHopsEnc(name enc.Name) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if name == nil {
		return // don't clear root
	}

	node := f.root.findExactMatchEntryEnc(name)
	if node != nil {
		node.nexthops = make([]*FibNextHopEntry, 0)
	}
}

// RemoveNextHop removes the specified nexthop entry from the specified prefix.
func (f *FibStrategyTree) RemoveNextHopEnc(name enc.Name, nexthop uint64) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	entry := f.root.findExactMatchEntryEnc(name)
	if entry != nil {
		for i, nh := range entry.nexthops {
			if nh.Nexthop == nexthop {
				if i < len(entry.nexthops)-1 {
					copy(entry.nexthops[i:], entry.nexthops[i+1:])
				}
				entry.nexthops = entry.nexthops[:len(entry.nexthops)-1]
				break
			}
		}
		entry.pruneIfEmpty()
	}
}

// GetNumFIBEntries returns the number of nexthop entries in the FIB.
func (f *FibStrategyTree) GetNumFIBEntries() int {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	count := 0
	f.walk(func(entry *fibStrategyTreeEntry) {
		count++
	})
	return count
}

// GetAllFIBEntries returns all nexthop entries in the FIB.
func (f *FibStrategyTree) GetAllFIBEntries() []FibStrategyEntry {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	entries := make([]FibStrategyEntry, 0)
	f.walk(func(entry *fibStrategyTreeEntry) {
		if len(entry.nexthops) > 0 {
			entries = append(entries, entry)
		}
	})
	return entries
}

// SetStrategy sets the strategy for the specified prefix.
func (f *FibStrategyTree) SetStrategyEnc(name enc.Name, strategy enc.Name) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	entry := f.fillTreeToPrefixEnc(name)
	entry.strategy = strategy.Clone()
}

// UnsetStrategy unsets the strategy for the specified prefix.
func (f *FibStrategyTree) UnSetStrategyEnc(name enc.Name) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	entry := f.root.findExactMatchEntryEnc(name)
	if entry != nil {
		entry.strategy = nil
		entry.pruneIfEmpty()
	}
}

// GetAllForwardingStrategies returns all strategy choice entries in the Strategy Table.
func (f *FibStrategyTree) GetAllForwardingStrategies() []FibStrategyEntry {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	entries := make([]FibStrategyEntry, 0)
	f.walk(func(entry *fibStrategyTreeEntry) {
		if entry.strategy != nil {
			entries = append(entries, entry)
		}
	})
	return entries
}

// walk walks the tree in-order, calling the specified function on each node.
func (f *FibStrategyTree) walk(fn func(*fibStrategyTreeEntry)) {
	queue := list.New()
	queue.PushBack(f.root)
	for queue.Len() > 0 {
		entry := queue.Front().Value.(*fibStrategyTreeEntry)
		queue.Remove(queue.Front())
		for _, child := range entry.children {
			queue.PushFront(child)
		}
		fn(entry)
	}
}
