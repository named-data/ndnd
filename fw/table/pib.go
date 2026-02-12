/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2025 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"container/list"
	"sort"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
)

// PibNextHop represents a next hop in the PIB.
type PibNextHop struct {
	FaceID uint64
	Cost   uint64
}

// PibEntry represents a snapshot of a PIB entry.
type PibEntry struct {
	Name          enc.Name
	EgressRouters []enc.Name
	NextHops      []PibNextHop
}

type pibEntryState struct {
	name     enc.Name
	egress   map[uint64]enc.Name
	nextHops map[uint64]PibNextHop
}

func (e *pibEntryState) snapshot() PibEntry {
	entry := PibEntry{
		Name:          e.name.Clone(),
		EgressRouters: make([]enc.Name, 0, len(e.egress)),
		NextHops:      make([]PibNextHop, 0, len(e.nextHops)),
	}

	for _, egress := range e.egress {
		entry.EgressRouters = append(entry.EgressRouters, egress.Clone())
	}
	for _, nh := range e.nextHops {
		entry.NextHops = append(entry.NextHops, nh)
	}

	sort.Slice(entry.EgressRouters, func(i, j int) bool {
		return entry.EgressRouters[i].String() < entry.EgressRouters[j].String()
	})
	sort.Slice(entry.NextHops, func(i, j int) bool {
		return entry.NextHops[i].FaceID < entry.NextHops[j].FaceID
	})

	return entry
}

type pibNode struct {
	name      enc.Name
	component enc.Component
	depth     int

	parent   *pibNode
	children map[uint64]*pibNode

	entry *pibEntryState
}

// PibTable represents the Prefix Information Base (PIB).
type PibTable struct {
	root  pibNode
	mutex sync.RWMutex
}

// Pib is the global Prefix Information Base.
var Pib = PibTable{
	root: pibNode{
		children: make(map[uint64]*pibNode),
	},
}

// (AI GENERATED DESCRIPTION): Returns the literal string "pib" to identify the PIB table in logs.
func (p *PibTable) String() string {
	return "pib"
}

func (n *pibNode) findExactMatchEntryEnc(name enc.Name) *pibNode {
	match := n.findLongestPrefixEntryEnc(name)
	if len(name) == len(match.name) {
		return match
	}
	return nil
}

func (n *pibNode) findLongestPrefixEntryEnc(name enc.Name) *pibNode {
	if len(name) > n.depth {
		if child, ok := n.children[At(name, n.depth).Hash()]; ok {
			return child.findLongestPrefixEntryEnc(name)
		}
	}
	return n
}

func (n *pibNode) fillTreeToPrefixEnc(name enc.Name) *pibNode {
	entry := n.findLongestPrefixEntryEnc(name)

	for depth := entry.depth; depth < len(name); depth++ {
		component := At(name, depth).Clone()
		child := &pibNode{
			name:      entry.name.Append(component),
			component: component,
			depth:     depth + 1,
			parent:    entry,
			children:  make(map[uint64]*pibNode),
		}
		entry.children[component.Hash()] = child
		entry = child
	}
	return entry
}

func (n *pibNode) pruneIfEmpty() {
	for entry := n; entry.parent != nil && entry.entry == nil && len(entry.children) == 0; entry = entry.parent {
		delete(entry.parent.children, entry.component.Hash())
		entry.parent = nil
	}
}

func (p *PibTable) getOrCreateEntry(node *pibNode, name enc.Name) *pibEntryState {
	if node.entry == nil {
		node.entry = &pibEntryState{
			name:     name.Clone(),
			egress:   make(map[uint64]enc.Name),
			nextHops: make(map[uint64]PibNextHop),
		}
	}
	return node.entry
}

// AddEgressEnc adds an egress router for the specified prefix.
func (p *PibTable) AddEgressEnc(prefix enc.Name, egress enc.Name) {
	if len(prefix) == 0 || len(egress) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	node := p.root.fillTreeToPrefixEnc(prefix)
	entry := p.getOrCreateEntry(node, prefix)
	entry.egress[egress.Hash()] = egress.Clone()
}

// RemoveEgressEnc removes an egress router from the specified prefix.
func (p *PibTable) RemoveEgressEnc(prefix enc.Name, egress enc.Name) {
	if len(prefix) == 0 || len(egress) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	node := p.root.findExactMatchEntryEnc(prefix)
	if node == nil || node.entry == nil {
		return
	}

	delete(node.entry.egress, egress.Hash())
	if len(node.entry.egress) == 0 && len(node.entry.nextHops) == 0 {
		node.entry = nil
		node.pruneIfEmpty()
	}
}

// AddNextHopEnc adds or updates a nexthop for the specified prefix.
func (p *PibTable) AddNextHopEnc(prefix enc.Name, faceID uint64, cost uint64) {
	if len(prefix) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	node := p.root.fillTreeToPrefixEnc(prefix)
	entry := p.getOrCreateEntry(node, prefix)
	entry.nextHops[faceID] = PibNextHop{FaceID: faceID, Cost: cost}
}

// RemoveNextHopEnc removes a nexthop for the specified prefix.
func (p *PibTable) RemoveNextHopEnc(prefix enc.Name, faceID uint64) {
	if len(prefix) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	node := p.root.findExactMatchEntryEnc(prefix)
	if node == nil || node.entry == nil {
		return
	}

	delete(node.entry.nextHops, faceID)
	if len(node.entry.egress) == 0 && len(node.entry.nextHops) == 0 {
		node.entry = nil
		node.pruneIfEmpty()
	}
}

// FindExactEnc returns a snapshot of the PIB entry for the exact prefix.
func (p *PibTable) FindExactEnc(prefix enc.Name) (PibEntry, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	node := p.root.findExactMatchEntryEnc(prefix)
	if node == nil || node.entry == nil {
		return PibEntry{}, false
	}
	return node.entry.snapshot(), true
}

// FindLongestPrefixEnc returns a snapshot of the longest-prefix matching PIB entry.
func (p *PibTable) FindLongestPrefixEnc(name enc.Name) (PibEntry, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	node := p.root.findLongestPrefixEntryEnc(name)
	for node != nil && node.entry == nil {
		node = node.parent
	}
	if node == nil || node.entry == nil {
		return PibEntry{}, false
	}
	return node.entry.snapshot(), true
}

// GetAllEntries returns snapshots of all PIB entries.
func (p *PibTable) GetAllEntries() []PibEntry {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	entries := make([]PibEntry, 0)
	queue := list.New()
	queue.PushBack(&p.root)

	for queue.Len() > 0 {
		node := queue.Front().Value.(*pibNode)
		queue.Remove(queue.Front())

		for _, child := range node.children {
			queue.PushFront(child)
		}

		if node.entry != nil {
			entries = append(entries, node.entry.snapshot())
		}
	}

	return entries
}
