/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
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

// (AI GENERATED DESCRIPTION): Tests that the FibStrategyTable correctly inserts, looks up, removes, and prunes next‑hop entries for encoded name prefixes, including longest‑prefix matching behavior.
func TestNdnFindNextHops(t *testing.T) {
	newFibStrategyTableTree()

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

// (AI GENERATED DESCRIPTION): Tests setting, unsetting, and pruning of strategy entries in the FIB strategy table tree, verifying that strategy lookups return the correct strategy names.
func TestNdnFind_Set_Unset_Strategy(t *testing.T) {
	newFibStrategyTableTree()

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

// (AI GENERATED DESCRIPTION): Verifies that inserting a next‑hop into the FIB strategy table correctly adds the entry, updates its cost on subsequent insertion, and that the hop can be retrieved accurately.
func TestNdnInsertNextHop(t *testing.T) {
	newFibStrategyTableTree()
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

// (AI GENERATED DESCRIPTION): Clears all next‑hop entries associated with a specified name in the FIB strategy table, removing only exact matches while leaving other names and non‑existent entries untouched.
func TestNdnClearNextHops(t *testing.T) {
	newFibStrategyTableTree()
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

// (AI GENERATED DESCRIPTION): Verifies that next‑hop entries can be inserted, updated in place, and removed from the FIB strategy table, ensuring each operation only affects the intended name prefix and that distinct prefixes remain independent.
func TestNdnRemoveNextHop(t *testing.T) {
	newFibStrategyTableTree()
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

// (AI GENERATED DESCRIPTION): Tests that `GetAllFIBEntries` returns all entries from the FibStrategyTable with correct strategy and next‑hop data, excluding entries that have neither a strategy nor next hops.
func TestNdnGetAllFIBEntries(t *testing.T) {
	newFibStrategyTableTree()
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

// (AI GENERATED DESCRIPTION): Verifies that GetAllForwardingStrategies correctly returns all configured strategies in the FIB tree, including the default, per‑prefix strategies, and their associated next‑hop entries.
func TestNdnGetAllForwardingStrategies(t *testing.T) {
	newFibStrategyTableTree()
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
