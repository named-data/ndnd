/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	enc "github.com/named-data/ndnd/std/encoding"
)

// FibStrategyEntry represents an entry in the FIB-Strategy table.
type FibStrategyEntry interface {
	Name() enc.Name
	GetStrategy() enc.Name
	GetNextHops() []*FibNextHopEntry
}

// baseFibStrategyEntry represents information that all
// FibStrategyEntry implementations should include.
type baseFibStrategyEntry struct {
	component enc.Component
	name      enc.Name
	nexthops  []*FibNextHopEntry
	strategy  enc.Name
	// strategyHash caches strategy.Hash() for lookups in the forwarding threads
	strategyHash uint64
}

// FibNextHopEntry represents a nexthop in a FIB entry.
type FibNextHopEntry struct {
	Nexthop uint64
	Cost    uint64
}

// FibStrategy represents the functionality that a FIB-strategy table should implement.
type FibStrategy interface {
	FindNextHopsEnc(name enc.Name) []*FibNextHopEntry
	FindStrategyEnc(name enc.Name) enc.Name
	// FindNextHopsAndStrategyEnc returns the nexthops (appended to buf[:0]) and strategy hash for name.
	FindNextHopsAndStrategyEnc(name enc.Name, buf []*FibNextHopEntry) ([]*FibNextHopEntry, uint64)
	// FindStrategyHashEnc returns the hash of the longest-prefix matching strategy name.
	FindStrategyHashEnc(name enc.Name) uint64
	InsertNextHopEnc(name enc.Name, nextHop uint64, cost uint64)
	ClearNextHopsEnc(name enc.Name)
	RemoveNextHopEnc(name enc.Name, nextHop uint64)
	GetNumFIBEntries() int
	GetAllFIBEntries() []FibStrategyEntry
	SetStrategyEnc(name enc.Name, strategy enc.Name)
	UnSetStrategyEnc(name enc.Name)
	GetAllForwardingStrategies() []FibStrategyEntry
}

// FibStrategy is a table containing FIB and Strategy entries for given prefixes.
var FibStrategyTable FibStrategy

// Name returns the name associated with the baseFibStrategyEntry.
func (e *baseFibStrategyEntry) Name() enc.Name {
	return e.name
}

// GetStrategy returns the strategy associated with the baseFibStrategyEntry.
func (e *baseFibStrategyEntry) GetStrategy() enc.Name {
	return e.strategy
}

// GetNexthops gets the nexthops of the specified entry.
func (e *baseFibStrategyEntry) GetNextHops() []*FibNextHopEntry {
	return e.nexthops
}

// setStrategy sets the strategy of the entry and caches its hash.
func (e *baseFibStrategyEntry) setStrategy(strategy enc.Name) {
	e.strategy = strategy
	if strategy != nil {
		e.strategyHash = strategy.Hash()
	} else {
		e.strategyHash = 0
	}
}
