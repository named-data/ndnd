/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2022 Danning Yu.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"sort"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/stretchr/testify/assert"
)

// (AI GENERATED DESCRIPTION): Verifies that the FIB strategy table correctly inserts, retrieves,
// and removes encoded next‑hop entries, supports longest‑prefix matching,
// and prunes unused entries in a hash‑table implementation.
func TestFindNextHopsEncEnc_HT(t *testing.T) {
	newFibStrategyTableHashTable(1)

	assert.NotNil(t, FibStrategyTable)

	// Root entry has no hops
	name1, _ := enc.NameFromStr("/")
	nexthops1 := FibStrategyTable.FindNextHopsEnc(name1)
	assert.Equal(t, 0, len(nexthops1))

	// Next hops need to be explicitly added
	name2, _ := enc.NameFromStr("/test")
	nexthops2 := FibStrategyTable.FindNextHopsEnc(name2)
	assert.Equal(t, 0, len(nexthops2))
	FibStrategyTable.InsertNextHopEnc(name2, 25, 1)
	FibStrategyTable.InsertNextHopEnc(name2, 101, 10)
	nexthops2a := FibStrategyTable.FindNextHopsEnc(name2)
	assert.Equal(t, 2, len(nexthops2a))
	assert.Equal(t, uint64(25), nexthops2a[0].Nexthop)
	assert.Equal(t, uint64(1), nexthops2a[0].Cost)
	assert.Equal(t, uint64(101), nexthops2a[1].Nexthop)
	assert.Equal(t, uint64(10), nexthops2a[1].Cost)

	// Check longest prefix match, should match with /test
	// and then return its next hops
	name3, _ := enc.NameFromStr("/test/name/202=abc123")
	nexthops3 := FibStrategyTable.FindNextHopsEnc(name3)
	assert.Equal(t, 2, len(nexthops3))
	assert.Equal(t, uint64(25), nexthops3[0].Nexthop)
	assert.Equal(t, uint64(1), nexthops3[0].Cost)
	assert.Equal(t, uint64(101), nexthops3[1].Nexthop)
	assert.Equal(t, uint64(10), nexthops3[1].Cost)
	nexthops1a := FibStrategyTable.FindNextHopsEnc(name1)
	assert.Equal(t, 0, len(nexthops1a))

	// Next hops should be updated when they're removed
	FibStrategyTable.RemoveNextHopEnc(name2, 25)
	nexthops2b := FibStrategyTable.FindNextHopsEnc(name2)
	assert.Equal(t, 1, len(nexthops2b))
	assert.Equal(t, uint64(101), nexthops2b[0].Nexthop)
	assert.Equal(t, uint64(10), nexthops2b[0].Cost)

	// Test pruning
	name4, _ := enc.NameFromStr("/test4")
	name5, _ := enc.NameFromStr("/test5")
	FibStrategyTable.InsertNextHopEnc(name4, 25, 1)
	FibStrategyTable.InsertNextHopEnc(name5, 25, 1)

	FibStrategyTable.RemoveNextHopEnc(name4, 25)
	nexthops2c := FibStrategyTable.FindNextHopsEnc(name4)
	assert.Equal(t, 0, len(nexthops2c))
}

// (AI GENERATED DESCRIPTION): Tests that the hash‑table based strategy table correctly finds the default strategy,
// sets and overrides strategies for specific prefixes, and unsets them,
// verifying the expected strategy is returned at each lookup.
func TestFind_Set_Unset_Strategy_HT(t *testing.T) {
	newFibStrategyTableHashTable(1)

	assert.NotNil(t, FibStrategyTable)

	bestRoute, _ := enc.NameFromStr("/localhost/nfd/strategy/best-route/v=1")
	multicast, _ := enc.NameFromStr("/localhost/nfd/strategy/multicast/v=1")

	name1, _ := enc.NameFromStr("/")
	assert.True(t, bestRoute.Equal(FibStrategyTable.FindStrategyEnc(name1)))

	name2, _ := enc.NameFromStr("/test")
	assert.True(t, bestRoute.Equal(FibStrategyTable.FindStrategyEnc(name2)))
	FibStrategyTable.SetStrategyEnc(name2, multicast)
	assert.True(t, bestRoute.Equal(FibStrategyTable.FindStrategyEnc(name1)))
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name2)))

	name3, _ := enc.NameFromStr("/test/name/202=abc123")
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name3)))
	FibStrategyTable.SetStrategyEnc(name3, bestRoute)
	assert.True(t, bestRoute.Equal(FibStrategyTable.FindStrategyEnc(name1)))
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name2)))
	assert.True(t, bestRoute.Equal(FibStrategyTable.FindStrategyEnc(name3)))

	// Test pruning
	FibStrategyTable.UnSetStrategyEnc(name3)
	assert.True(t, bestRoute.Equal(FibStrategyTable.FindStrategyEnc(name1)))
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name2)))
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name3)))

	FibStrategyTable.SetStrategyEnc(name1, multicast)
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name1)))
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name2)))
	assert.True(t, multicast.Equal(FibStrategyTable.FindStrategyEnc(name3)))
}

// (AI GENERATED DESCRIPTION): Inserts or updates a next‑hop entry in the FIB strategy table for a given name,
// setting the specified next‑hop identifier and its cost (updating the cost if the entry already exists).
func TestInsertNextHopEnc_HT(t *testing.T) {
	newFibStrategyTableHashTable(1)
	assert.NotNil(t, FibStrategyTable)

	name, _ := enc.NameFromStr("/test/name")

	// Insert new hop
	FibStrategyTable.InsertNextHopEnc(name, 100, 10)
	nextHops := FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, uint64(100), nextHops[0].Nexthop)
	assert.Equal(t, uint64(10), nextHops[0].Cost)

	// Update cost of current hop
	FibStrategyTable.InsertNextHopEnc(name, 100, 20)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, uint64(100), nextHops[0].Nexthop)
	assert.NotEqual(t, uint64(10), nextHops[0].Cost)
	assert.Equal(t, uint64(20), nextHops[0].Cost)
}

// (AI GENERATED DESCRIPTION): Tests that FibStrategyTable.ClearNextHopsEnc correctly removes all
// next‑hop entries for a given name, leaving unrelated or longer names unaffected and handling
// non‑existent entries gracefully.
func TestClearNextHops_HT(t *testing.T) {
	newFibStrategyTableHashTable(1)
	assert.NotNil(t, FibStrategyTable)

	name, _ := enc.NameFromStr("/test/name")

	// Insert new hop
	FibStrategyTable.InsertNextHopEnc(name, 100, 10)
	FibStrategyTable.InsertNextHopEnc(name, 100, 20)
	FibStrategyTable.InsertNextHopEnc(name, 200, 10)
	FibStrategyTable.InsertNextHopEnc(name, 300, 10)

	nextHops := FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 3, len(nextHops))

	FibStrategyTable.ClearNextHopsEnc(name)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 0, len(nextHops))

	// Should have no effect on a name with no hops
	// Or an nonexistent name
	FibStrategyTable.ClearNextHopsEnc(name)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 0, len(nextHops))

	nameDoesNotExist, _ := enc.NameFromStr("/asdf")
	FibStrategyTable.ClearNextHopsEnc(nameDoesNotExist)
	nextHops = FibStrategyTable.FindNextHopsEnc(nameDoesNotExist)
	assert.Equal(t, 0, len(nextHops))

	// Should only clear hops for exact match
	FibStrategyTable.InsertNextHopEnc(name, 100, 10)
	nameLonger, _ := enc.NameFromStr("/test/name/longer")
	FibStrategyTable.InsertNextHopEnc(nameLonger, 200, 10)

	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 1, len(nextHops))
	FibStrategyTable.ClearNextHopsEnc(name)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 0, len(nextHops))

	nextHops = FibStrategyTable.FindNextHopsEnc(nameLonger)
	assert.Equal(t, 1, len(nextHops))
}

// (AI GENERATED DESCRIPTION): Tests that `RemoveNextHopEnc` correctly deletes specified
// next‑hop entries from the FIB strategy table for a given name, verifying the remaining
// hop count after each removal and ensuring entries for other names are not affected.
func TestRemoveNextHopEnc_HT(t *testing.T) {
	newFibStrategyTableHashTable(1)
	assert.NotNil(t, FibStrategyTable)

	name, _ := enc.NameFromStr("/test")

	// Insert new hop
	hopId1 := uint64(100)
	hopId2 := uint64(200)
	hopId3 := uint64(300)
	FibStrategyTable.InsertNextHopEnc(name, hopId1, 10)
	FibStrategyTable.InsertNextHopEnc(name, hopId2, 10)
	FibStrategyTable.InsertNextHopEnc(name, hopId3, 10)
	FibStrategyTable.InsertNextHopEnc(name, hopId1, 20) // updates it in place

	nextHops := FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 3, len(nextHops))

	FibStrategyTable.RemoveNextHopEnc(name, hopId1)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 2, len(nextHops))

	FibStrategyTable.RemoveNextHopEnc(name, hopId2)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 1, len(nextHops))

	FibStrategyTable.RemoveNextHopEnc(name, hopId3)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 0, len(nextHops))

	FibStrategyTable.InsertNextHopEnc(name, hopId1, 10)
	nameLonger, _ := enc.NameFromStr("/test/name/longer")
	FibStrategyTable.InsertNextHopEnc(nameLonger, hopId2, 10)

	FibStrategyTable.RemoveNextHopEnc(name, hopId1)
	nextHops = FibStrategyTable.FindNextHopsEnc(name)
	assert.Equal(t, 0, len(nextHops))
	nextHops = FibStrategyTable.FindNextHopsEnc(nameLonger)
	assert.Equal(t, 1, len(nextHops))
}

// (AI GENERATED DESCRIPTION): Tests that `GetAllFIBEntries` correctly returns all FIB entries with
// their associated strategy and next‑hop information, verifying proper handling of entries that have
// only a strategy, only next hops, or both.
func TestGetAllFIBEntries_HT(t *testing.T) {
	newFibStrategyTableHashTable(1)
	assert.NotNil(t, FibStrategyTable)

	bestRoute, _ := enc.NameFromStr("/localhost/nfd/strategy/best-route/v=1")
	multicast, _ := enc.NameFromStr("/localhost/nfd/strategy/multicast/v=1")

	hopId2 := uint64(200)
	hopId3 := uint64(300)

	// Only strategy, no next hops, so it shouldn't be returned
	name, _ := enc.NameFromStr("/test")
	FibStrategyTable.SetStrategyEnc(name, multicast)

	name2, _ := enc.NameFromStr("/test/name/202=abc123")
	FibStrategyTable.SetStrategyEnc(name2, bestRoute)
	FibStrategyTable.InsertNextHopEnc(name2, hopId2, 20)
	FibStrategyTable.InsertNextHopEnc(name2, hopId3, 30)

	// name3 has no strategy
	name3, _ := enc.NameFromStr("/test/name_second/202=abc123")
	FibStrategyTable.InsertNextHopEnc(name3, hopId3, 40)
	FibStrategyTable.InsertNextHopEnc(name3, hopId3, 50)

	fse := FibStrategyTable.GetAllFIBEntries()
	assert.Equal(t, 2, len(fse))

	sort.Slice(fse, func(i, j int) bool {
		// Sort by name
		return fse[i].Name().String() < fse[j].Name().String()
	})

	assert.True(t, name2.Equal(fse[0].Name()))
	assert.True(t, bestRoute.Equal(fse[0].GetStrategy()))
	nextHops := fse[0].GetNextHops()
	assert.Equal(t, 2, len(nextHops))
	assert.Equal(t, hopId2, nextHops[0].Nexthop)
	assert.Equal(t, uint64(20), nextHops[0].Cost)
	assert.Equal(t, hopId3, nextHops[1].Nexthop)
	assert.Equal(t, uint64(30), nextHops[1].Cost)

	// Only next hops, no strategy
	assert.True(t, name3.Equal(fse[1].Name()))
	assert.Nil(t, fse[1].GetStrategy())
	nextHops = fse[1].GetNextHops()
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, hopId3, nextHops[0].Nexthop)
	assert.Equal(t, uint64(50), nextHops[0].Cost)
}

// (AI GENERATED DESCRIPTION): Tests that GetAllForwardingStrategies correctly returns all configured forwarding strategies and their associated next hop information from the strategy table.
func TestGetAllForwardingStrategies_HT(t *testing.T) {
	newFibStrategyTableHashTable(1)
	assert.NotNil(t, FibStrategyTable)

	bestRoute, _ := enc.NameFromStr("/localhost/nfd/strategy/best-route/v=1")
	multicast, _ := enc.NameFromStr("/localhost/nfd/strategy/multicast/v=1")

	hopId2 := uint64(200)
	hopId3 := uint64(300)

	// No strategy, so it shouldn't be included
	name, _ := enc.NameFromStr("/test")
	FibStrategyTable.InsertNextHopEnc(name, hopId2, 20)

	name2, _ := enc.NameFromStr("/test/name/202=abc123")
	FibStrategyTable.SetStrategyEnc(name2, bestRoute)
	FibStrategyTable.InsertNextHopEnc(name2, hopId2, 20)
	FibStrategyTable.InsertNextHopEnc(name2, hopId3, 30)

	name3, _ := enc.NameFromStr("/test/name_second/202=abc123")
	FibStrategyTable.SetStrategyEnc(name3, multicast)

	fse := FibStrategyTable.GetAllForwardingStrategies()
	// Here, the "/" has a default strategy, bestRoute in this case
	assert.Equal(t, 3, len(fse))

	sort.Slice(fse, func(i, j int) bool {
		// Sort by name
		return fse[i].Name().String() < fse[j].Name().String()
	})

	rootName, _ := enc.NameFromStr("/")
	assert.True(t, rootName.Equal(fse[0].Name()))
	assert.True(t, bestRoute.Equal(fse[0].GetStrategy()))

	assert.True(t, name2.Equal(fse[1].Name()))
	assert.True(t, bestRoute.Equal(fse[1].GetStrategy()))
	nextHops := fse[1].GetNextHops()
	assert.Equal(t, 2, len(nextHops))
	assert.Equal(t, hopId2, nextHops[0].Nexthop)
	assert.Equal(t, uint64(20), nextHops[0].Cost)
	assert.Equal(t, hopId3, nextHops[1].Nexthop)
	assert.Equal(t, uint64(30), nextHops[1].Cost)

	assert.True(t, name3.Equal(fse[2].Name()))
	assert.True(t, multicast.Equal(fse[2].GetStrategy()))
	nextHops = fse[2].GetNextHops()
	assert.Equal(t, 0, len(nextHops))
}

// (AI GENERATED DESCRIPTION): Tests the hash‑table based FIB strategy table implementation by inserting, querying, and deleting next‑hop entries, verifying correct longest‑prefix matches, pruning logic, and strategy handling.
func testFIB_HT_Details(t *testing.T, m uint16) {
	// A test suite specific to the hash table approach
	newFibStrategyTableHashTable(m)
	assert.NotNil(t, FibStrategyTable)

	name1, _ := enc.NameFromStr("/a")
	name2, _ := enc.NameFromStr("/a/b/d")
	name3, _ := enc.NameFromStr("/a/b/c")
	name4, _ := enc.NameFromStr("/a/b/d/e")
	name5, _ := enc.NameFromStr("/a/b/d/e/f")
	nameNonexistent, _ := enc.NameFromStr(("/asdfasdf"))

	hopId1 := uint64(10)
	hopId2 := uint64(11)
	hopId3 := uint64(12)
	hopId4a := uint64(13)
	hopId4b := uint64(14)
	hopId5 := uint64(15)

	cost := uint64(1)

	FibStrategyTable.InsertNextHopEnc(name1, hopId1, cost)
	FibStrategyTable.InsertNextHopEnc(name2, hopId2, cost)
	FibStrategyTable.InsertNextHopEnc(name3, hopId3, cost)
	FibStrategyTable.InsertNextHopEnc(name4, hopId4a, cost)
	FibStrategyTable.InsertNextHopEnc(name4, hopId4b, cost)
	FibStrategyTable.InsertNextHopEnc(name5, hopId5, cost)

	nextHopsEmpty := FibStrategyTable.FindNextHopsEnc(nameNonexistent)
	assert.Equal(t, 0, len(nextHopsEmpty))

	nameSearch1, _ := enc.NameFromStr("/a/b/c/d/e/f")
	// match /a/b/c
	nextHops1 := FibStrategyTable.FindNextHopsEnc(nameSearch1)
	assert.Equal(t, 1, len(nextHops1))
	assert.Equal(t, hopId3, nextHops1[0].Nexthop)
	assert.Equal(t, cost, nextHops1[0].Cost)

	nameSearch2, _ := enc.NameFromStr("/a/c/d/e/f/g")
	// match /a
	nextHops2 := FibStrategyTable.FindNextHopsEnc(nameSearch2)
	assert.Equal(t, 1, len(nextHops2))
	assert.Equal(t, hopId1, nextHops2[0].Nexthop)
	assert.Equal(t, cost, nextHops2[0].Cost)

	nextHops3 := FibStrategyTable.FindNextHopsEnc(name1)
	// match /a
	assert.Equal(t, 1, len(nextHops3))
	assert.Equal(t, hopId1, nextHops3[0].Nexthop)
	assert.Equal(t, cost, nextHops3[0].Cost)

	nameSearch3, _ := enc.NameFromStr("/a/b/d/e/zzz")
	// match /a/b/d/e
	nextHops4 := FibStrategyTable.FindNextHopsEnc(nameSearch3)
	assert.Equal(t, 2, len(nextHops4))
	assert.Equal(t, hopId4a, nextHops4[0].Nexthop)
	assert.Equal(t, cost, nextHops4[0].Cost)
	assert.Equal(t, hopId4b, nextHops4[1].Nexthop)
	assert.Equal(t, cost, nextHops4[1].Cost)

	nameSearch4, _ := enc.NameFromStr("/a/b/d/e/f/g/h")
	// match /a/b/d/e/f
	nextHops5 := FibStrategyTable.FindNextHopsEnc(nameSearch4)
	assert.Equal(t, 1, len(nextHops5))
	assert.Equal(t, hopId5, nextHops5[0].Nexthop)
	assert.Equal(t, cost, nextHops5[0].Cost)

	nameSearch5, _ := enc.NameFromStr("/b")
	// match nothing
	nextHops6 := FibStrategyTable.FindNextHopsEnc(nameSearch5)
	assert.Equal(t, 0, len(nextHops6))

	nameSearch6, _ := enc.NameFromStr("/z/y/x/w/v/u/t")
	// match nothing
	nextHops7 := FibStrategyTable.FindNextHopsEnc(nameSearch6)
	assert.Equal(t, 0, len(nextHops7))

	// Deletions
	// Delete nonexistent name or face
	FibStrategyTable.RemoveNextHopEnc(nameNonexistent, uint64(0))
	FibStrategyTable.RemoveNextHopEnc(name1, uint64(0))

	// Delete with name and outFace that exists
	FibStrategyTable.RemoveNextHopEnc(name4, hopId4b)
	nextHops := FibStrategyTable.FindNextHopsEnc(name4)
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, hopId4a, nextHops4[0].Nexthop)
	assert.Equal(t, cost, nextHops4[0].Cost)

	FibStrategyTable.RemoveNextHopEnc(name4, hopId4a)
	// This should only match name2 now: /a/b/d
	nextHops = FibStrategyTable.FindNextHopsEnc(name4)
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, hopId2, nextHops[0].Nexthop)
	assert.Equal(t, cost, nextHops[0].Cost)

	FibStrategyTable.RemoveNextHopEnc(name3, hopId3)
	// This should only match name1 now: /a
	nextHops = FibStrategyTable.FindNextHopsEnc(name3)
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, hopId1, nextHops[0].Nexthop)
	assert.Equal(t, cost, nextHops[0].Cost)

	// This should trigger pruning
	FibStrategyTable.RemoveNextHopEnc(name5, hopId5)
	nextHops = FibStrategyTable.FindNextHopsEnc(name5)
	// This should only match name2 now: /a/b/d
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, hopId2, nextHops[0].Nexthop)
	assert.Equal(t, cost, nextHops[0].Cost)

	FibStrategyTable.RemoveNextHopEnc(name1, hopId1)
	nextHops = FibStrategyTable.FindNextHopsEnc(name1)
	assert.Equal(t, 0, len(nextHops))

	nextHops = FibStrategyTable.FindNextHopsEnc(name2)
	assert.Equal(t, 1, len(nextHops))
	assert.Equal(t, hopId2, nextHops[0].Nexthop)
	assert.Equal(t, cost, nextHops[0].Cost)

	FibStrategyTable.RemoveNextHopEnc(name2, hopId2)

	// No entries left in FIB, everything should be removed
	nextHops = FibStrategyTable.FindNextHopsEnc(name1)
	assert.Equal(t, 0, len(nextHops))
	nextHops = FibStrategyTable.FindNextHopsEnc(name2)
	assert.Equal(t, 0, len(nextHops))
	nextHops = FibStrategyTable.FindNextHopsEnc(name3)
	assert.Equal(t, 0, len(nextHops))
	nextHops = FibStrategyTable.FindNextHopsEnc(name4)
	assert.Equal(t, 0, len(nextHops))
	nextHops = FibStrategyTable.FindNextHopsEnc(name5)
	assert.Equal(t, 0, len(nextHops))

	// Eliminate the root name from tree too
	// This results in an empty hash table
	rootName, _ := enc.NameFromStr("/")
	FibStrategyTable.UnSetStrategyEnc(rootName)
	nextHops = FibStrategyTable.FindNextHopsEnc(name1)
	assert.Equal(t, 0, len(nextHops))
	nextHops = FibStrategyTable.FindNextHopsEnc(name5)
	assert.Equal(t, 0, len(nextHops))
	strategy := FibStrategyTable.FindStrategyEnc(name1)
	assert.Nil(t, strategy)

	// Nexthop entry exists but not root strategy
	FibStrategyTable.InsertNextHopEnc(name1, hopId1, cost)
	strategy = FibStrategyTable.FindStrategyEnc(name1)
	assert.Nil(t, strategy)
}

// (AI GENERATED DESCRIPTION): Runs hashtable‐based FIB tests over several table sizes to validate the handling of real and virtual nodes.
func TestFIB_HT_RealAndVirtualNodes(t *testing.T) {
	// Hashtable specific tests, for different values of m
	for i := 1; i < 8; i++ {
		testFIB_HT_Details(t, uint16(i))
	}
}
