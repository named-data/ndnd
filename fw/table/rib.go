/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2022 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"container/list"
	"sync"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// RibTable represents the Routing Information Base (RIB).
type RibTable struct {
	root  RibEntry
	mutex sync.RWMutex
}

// RibEntry represents an entry in the RIB table.
type RibEntry struct {
	Name      enc.Name
	component enc.Component
	depth     int

	parent   *RibEntry
	children map[uint64]*RibEntry

	routes []*Route
}

// Route represents a route in a RIB entry.
type Route struct {
	FaceID           uint64
	Origin           uint64
	Cost             uint64
	Flags            uint64
	ExpirationPeriod *time.Duration
}

// Rib is the Routing Information Base.
var Rib = RibTable{
	root: RibEntry{
		children: make(map[uint64]*RibEntry),
	},
}

func (r *RibEntry) fillTreeToPrefixEnc(name enc.Name) *RibEntry {
	entry := r.findLongestPrefixEntryEnc(name)

	for depth := entry.depth; depth < len(name); depth++ {
		component := At(name, depth).Clone()
		child := &RibEntry{
			Name:      name[:depth+1].Clone(),
			depth:     depth + 1,
			component: component,
			parent:    entry,
			children:  make(map[uint64]*RibEntry),
		}
		entry.children[component.Hash()] = child
		entry = child
	}
	return entry
}
func (r *RibEntry) findExactMatchEntryEnc(name enc.Name) *RibEntry {
	match := r.findLongestPrefixEntryEnc(name)
	if len(name) == len(match.Name) {
		return match
	}
	return nil
}

func (r *RibEntry) findLongestPrefixEntryEnc(name enc.Name) *RibEntry {
	if len(name) > r.depth {
		if child := r.children[At(name, r.depth).Hash()]; child != nil {
			return child.findLongestPrefixEntryEnc(name)
		}
	}
	return r
}

func (r *RibEntry) pruneIfEmpty() {
	for entry := r; entry != nil && len(entry.children) == 0 && len(entry.routes) == 0; entry = entry.parent {
		// Remove from parent's children
		if entry.parent != nil {
			delete(entry.parent.children, entry.component.Hash())
		}

		// Unlink parent from child for inheritance pruning.
		entry.parent = nil
	}
}

// updateNexthopsEnc recursively updates the FIB nexthops under this entry.
func (r *RibEntry) updateNexthopsEnc() {
	FibStrategyTable.ClearNextHopsEnc(r.Name)

	// All routes including parents if needed
	routes := append([]*Route{}, r.routes...)

	// Get all possible nexthops for parents that are inherited,
	// unless we have the capture flag set
	if !r.HasCaptureRoute() {
		for entry := r; entry != nil; entry = entry.parent {
			for _, route := range entry.routes {
				if route.HasChildInheritFlag() {
					routes = append(routes, route)
				}
			}
		}
	}

	// Find minimum cost route per nexthop
	minCostRoutes := make(map[uint64]uint64) // FaceID -> Cost
	for _, route := range routes {
		cost, ok := minCostRoutes[route.FaceID]
		if !ok || route.Cost < cost {
			minCostRoutes[route.FaceID] = route.Cost
		}
	}

	// Add "flattened" set of nexthops
	for nexthop, cost := range minCostRoutes {
		FibStrategyTable.InsertNextHopEnc(r.Name, nexthop, cost)
	}

	// Trigger update for all children for inheritance
	for _, child := range r.children {
		child.updateNexthopsEnc()
	}
}

// AddRoute adds or updates a RIB entry for the specified prefix.
func (r *RibTable) AddEncRoute(name enc.Name, route *Route) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	node := r.root.fillTreeToPrefixEnc(name)

	defer node.updateNexthopsEnc()

	for _, existingRoute := range node.routes {
		if existingRoute.FaceID == route.FaceID && existingRoute.Origin == route.Origin {
			existingRoute.Cost = route.Cost
			existingRoute.Flags = route.Flags
			existingRoute.ExpirationPeriod = route.ExpirationPeriod
			return
		}
	}

	node.routes = append(node.routes, route)
	readvertiseAnnounce(name, route)
}

// GetAllEntries returns all routes in the RIB.
func (r *RibTable) GetAllEntries() []*RibEntry {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	entries := make([]*RibEntry, 0)
	// Walk tree in-order
	queue := list.New()
	queue.PushBack(&r.root)
	for queue.Len() > 0 {
		ribEntry := queue.Front().Value.(*RibEntry)
		queue.Remove(queue.Front())
		// Add all children to stack
		for _, child := range ribEntry.children {
			queue.PushFront(child)
		}

		// If has any routes, add to list
		if len(ribEntry.routes) > 0 {
			entries = append(entries, ribEntry)
		}
	}
	return entries
}

// RemoveRoute removes the specified route from the specified prefix.
func (r *RibTable) RemoveRouteEnc(name enc.Name, faceID uint64, origin uint64) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	entry := r.root.findExactMatchEntryEnc(name)
	if entry == nil {
		return
	}

	for i, route := range entry.routes {
		if route.FaceID == faceID && route.Origin == origin {
			if i < len(entry.routes)-1 {
				copy(entry.routes[i:], entry.routes[i+1:])
			}
			entry.routes = entry.routes[:len(entry.routes)-1]
			readvertiseWithdraw(name, route)
			break
		}
	}

	entry.pruneIfEmpty()
	entry.updateNexthopsEnc() // recursive
}

func (r *RibTable) CleanUpFace(faceId uint64) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// This currently walks the entire tree, but this can be optimized if needed
	r.root.cleanUpFace(faceId)
}

// GetRoutes returns all routes in the RIB entry.
func (r *RibEntry) GetRoutes() []*Route {
	return r.routes
}

// CleanUpFace removes the specified face from all entries.
// Used for clean-up after a face is destroyed.
func (r *RibEntry) cleanUpFace(faceId uint64) {
	for _, child := range r.children {
		child.cleanUpFace(faceId)
	}

	for i, route := range r.routes {
		if route.FaceID == faceId {
			if i < len(r.routes)-1 {
				copy(r.routes[i:], r.routes[i+1:])
			}
			r.routes = r.routes[:len(r.routes)-1]
			readvertiseWithdraw(r.Name, route)

			// entry changed, check and update FIB
			r.pruneIfEmpty()
			r.updateNexthopsEnc() // recursive
			return
		}
	}
}

func (r *RibEntry) HasCaptureRoute() bool {
	for _, route := range r.routes {
		if route.HasCaptureFlag() {
			return true
		}
	}
	return false
}

func (r *Route) HasCaptureFlag() bool {
	return r.Flags&uint64(spec_mgmt.RouteFlagCapture) != 0
}

func (r *Route) HasChildInheritFlag() bool {
	return r.Flags&uint64(spec_mgmt.RouteFlagChildInherit) != 0
}
