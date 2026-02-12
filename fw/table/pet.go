/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2026 Eric Newberry, Tianyuan Yu.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"sort"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
)

// PetEntry represents a snapshot of a Prefix Egress Table (PET) entry.
type PetEntry struct {
	Name          enc.Name
	EgressRouters []enc.Name
	Multicast     bool
}

type petEntryState struct {
	name      enc.Name
	egress    map[uint64]enc.Name
	multicast bool
}

func (e *petEntryState) snapshot() PetEntry {
	entry := PetEntry{
		Name:          e.name.Clone(),
		EgressRouters: make([]enc.Name, 0, len(e.egress)),
		Multicast:     e.multicast,
	}

	for _, egress := range e.egress {
		entry.EgressRouters = append(entry.EgressRouters, egress.Clone())
	}
	sort.Slice(entry.EgressRouters, func(i, j int) bool {
		return entry.EgressRouters[i].String() < entry.EgressRouters[j].String()
	})

	return entry
}

// PrefixEgressTable represents the Prefix Egress Table (PET).
type PrefixEgressTable struct {
	mutex   sync.RWMutex
	entries map[string]*petEntryState
}

// Pet is the global Prefix Egress Table.
var Pet = PrefixEgressTable{
	entries: make(map[string]*petEntryState),
}

func (p *PrefixEgressTable) String() string {
	return "pet"
}

func (p *PrefixEgressTable) getEntryLocked(prefix enc.Name) *petEntryState {
	key := prefix.TlvStr()
	entry := p.entries[key]
	if entry == nil {
		entry = &petEntryState{
			name:   prefix.Clone(),
			egress: make(map[uint64]enc.Name),
		}
		p.entries[key] = entry
	}
	return entry
}

func (p *PrefixEgressTable) pruneLocked(prefix enc.Name, entry *petEntryState) {
	if entry == nil {
		return
	}
	if len(entry.egress) == 0 && !entry.multicast {
		delete(p.entries, prefix.TlvStr())
	}
}

// SetEnc replaces the PET entry for the specified prefix.
func (p *PrefixEgressTable) SetEnc(prefix enc.Name, egress []enc.Name, multicast bool) {
	if len(prefix) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	entry := p.getEntryLocked(prefix)
	entry.egress = make(map[uint64]enc.Name, len(egress))
	for _, name := range egress {
		if len(name) == 0 {
			continue
		}
		entry.egress[name.Hash()] = name.Clone()
	}
	entry.multicast = multicast

	p.pruneLocked(prefix, entry)
}

// AddEgressEnc adds an egress router for the specified prefix.
func (p *PrefixEgressTable) AddEgressEnc(prefix enc.Name, egress enc.Name) {
	if len(prefix) == 0 || len(egress) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	entry := p.getEntryLocked(prefix)
	entry.egress[egress.Hash()] = egress.Clone()
}

// RemoveEgressEnc removes an egress router from the specified prefix.
func (p *PrefixEgressTable) RemoveEgressEnc(prefix enc.Name, egress enc.Name) {
	if len(prefix) == 0 || len(egress) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	entry := p.entries[prefix.TlvStr()]
	if entry == nil {
		return
	}
	delete(entry.egress, egress.Hash())
	p.pruneLocked(prefix, entry)
}

// SetMulticastEnc sets the multicast flag for the specified prefix.
func (p *PrefixEgressTable) SetMulticastEnc(prefix enc.Name, multicast bool) {
	if len(prefix) == 0 {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	entry := p.getEntryLocked(prefix)
	entry.multicast = multicast
	p.pruneLocked(prefix, entry)
}

// FindEnc returns a snapshot of the PET entry for the specified prefix.
func (p *PrefixEgressTable) FindEnc(prefix enc.Name) (PetEntry, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	entry := p.entries[prefix.TlvStr()]
	if entry == nil {
		return PetEntry{}, false
	}
	return entry.snapshot(), true
}

// GetAllEntries returns snapshots of all PET entries.
func (p *PrefixEgressTable) GetAllEntries() []PetEntry {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	entries := make([]PetEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry.snapshot())
	}
	return entries
}
