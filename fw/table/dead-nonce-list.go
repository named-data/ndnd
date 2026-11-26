/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
)

// DeadNonceList represents the Dead Nonce List for a forwarding thread.
//
// Entries are kept in two generations that are rotated every lifetime:
// new entries go into the current generation, and the previous generation
// is dropped on rotation. An entry is therefore kept for at least one and
// at most two lifetimes, with O(1) insertion and no per-entry expiry state.
type DeadNonceList struct {
	cur        map[uint64]struct{}
	prev       map[uint64]struct{}
	lifetime   time.Duration
	lastRotate time.Time
	Ticker     *time.Ticker
}

// NewDeadNonceList creates a new Dead Nonce List for a forwarding thread.
func NewDeadNonceList() *DeadNonceList {
	d := new(DeadNonceList)
	d.cur = make(map[uint64]struct{})
	d.prev = make(map[uint64]struct{})
	d.lifetime = max(CfgDeadNonceListLifetime(), time.Millisecond)
	d.lastRotate = time.Now()
	d.Ticker = time.NewTicker(d.lifetime)
	return d
}

// Find returns whether the specified name and nonce combination are present in the Dead Nonce List.
func (d *DeadNonceList) Find(name enc.Name, nonce uint32) bool {
	hash := name.Hash() + uint64(nonce)
	if _, ok := d.cur[hash]; ok {
		return true
	}
	_, ok := d.prev[hash]
	return ok
}

// Insert inserts an entry in the Dead Nonce List with the specified name and nonce.
// Returns whether nonce already present.
func (d *DeadNonceList) Insert(name enc.Name, nonce uint32) bool {
	hash := name.Hash() + uint64(nonce)
	if _, exists := d.cur[hash]; exists {
		return true
	}
	_, exists := d.prev[hash]

	// Always (re-)insert into the current generation so that
	// the entry lives for at least another lifetime.
	d.cur[hash] = struct{}{}
	return exists
}

// RemoveExpiredEntries drops the oldest generation of entries if it has
// been at least one lifetime since the last rotation.
func (d *DeadNonceList) RemoveExpiredEntries() {
	now := time.Now()
	if now.Sub(d.lastRotate) < d.lifetime {
		return
	}
	d.lastRotate = now

	// Reuse the dropped generation's map for the new current generation
	clear(d.prev)
	d.prev, d.cur = d.cur, d.prev
}

// Len returns the number of entries in the Dead Nonce List.
func (d *DeadNonceList) Len() int {
	return len(d.cur) + len(d.prev)
}
