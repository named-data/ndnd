/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"container/list"

	"github.com/named-data/ndnd/std/ndn"
)

// CsLRU is a least recently used (LRU) replacement policy for the Content Store.
type CsLRU struct {
	cs        PitCsTable
	queue     *list.List
	locations map[uint64]*list.Element
}

// NewCsLRU creates a new LRU replacement policy for the Content Store.
func NewCsLRU(cs PitCsTable) *CsLRU {
	l := new(CsLRU)
	l.cs = cs
	l.queue = list.New()
	l.locations = make(map[uint64]*list.Element)
	return l
}

// AfterInsert is called after a new entry is inserted into the Content Store.
func (l *CsLRU) AfterInsert(index uint64, wire []byte, data ndn.Data) {
	l.locations[index] = l.queue.PushBack(index)
}

// AfterRefresh is called after a new data packet refreshes an existing entry in the Content Store.
func (l *CsLRU) AfterRefresh(index uint64, wire []byte, data ndn.Data) {
	if location, ok := l.locations[index]; ok {
		l.queue.Remove(location)
	}
	l.locations[index] = l.queue.PushBack(index)
}

// BeforeErase is called before an entry is erased from the Content Store through management.
func (l *CsLRU) BeforeErase(index uint64, wire []byte) {
	if location, ok := l.locations[index]; ok {
		l.queue.Remove(location)
		delete(l.locations, index)
	}
}

// BeforeUse is called before an entry in the Content Store is used to satisfy a pending Interest.
func (l *CsLRU) BeforeUse(index uint64, wire []byte) {
	if location, ok := l.locations[index]; ok {
		l.queue.Remove(location)
	}
	l.locations[index] = l.queue.PushBack(index)
}

// EvictEntries is called to instruct the policy to evict enough entries to reduce the Content Store size
// below its size limit.
func (l *CsLRU) EvictEntries() {
	for l.queue.Len() > CfgCsCapacity() {
		indexToErase := l.queue.Front().Value.(uint64)
		l.cs.eraseCsDataFromReplacementStrategy(indexToErase) // TODO: find better name for this method
		l.queue.Remove(l.queue.Front())
	}
}
