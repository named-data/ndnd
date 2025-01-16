/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"sync/atomic"
	"time"

	"github.com/named-data/ndnd/fw/core"
	enc "github.com/named-data/ndnd/std/encoding"
)

// Mutable table configuration
var mutCfg = struct {
	csCapacity atomic.Int32
	csAdmit    atomic.Bool
	csServe    atomic.Bool
}{}

// Initialize creates tables and configuration.
func Initialize() {
	// Content Store
	mutCfg.csCapacity.Store(int32(core.C.Tables.ContentStore.Capacity))
	mutCfg.csAdmit.Store(core.C.Tables.ContentStore.Admit)
	mutCfg.csServe.Store(core.C.Tables.ContentStore.Serve)

	// Create FIB strategy table
	switch core.C.Tables.Fib.Algorithm {
	case "hashtable":
		newFibStrategyTableHashTable(core.C.Tables.Fib.Hashtable.M)
	case "nametree":
		newFibStrategyTableTree()
	default:
		core.Log.Fatal(nil, "Unknown FIB table algorithm", "algo", core.C.Tables.Fib.Algorithm)
	}

	// Create Network Region Table
	for _, region := range core.C.Tables.NetworkRegion.Regions {
		name, err := enc.NameFromStr(region)
		if err != nil {
			core.Log.Fatal(nil, "Could not add producer region", "name", region, "err", err)
		}
		NetworkRegion.Add(name)
		core.Log.Debug(nil, "Added producer region", "name", region)
	}
}

// CfgCsAdmit returns whether contents will be admitted to the Content Store.
func CfgCsAdmit() bool {
	return mutCfg.csAdmit.Load()
}

// CfgSetCsAdmit sets whether contents will be admitted to the Content Store.
func CfgSetCsAdmit(admit bool) {
	mutCfg.csAdmit.Store(admit)
}

// CfgCsServe returns whether contents will be served from the Content Store.
func CfgCsServe() bool {
	return mutCfg.csServe.Load()
}

// CfgSetCsServe sets whether contents will be served from the Content Store.
func CfgSetCsServe(serve bool) {
	mutCfg.csServe.Store(serve)
}

// CfgCsCapacity returns the capacity of each forwarding thread's Content Store.
func CfgCsCapacity() int {
	return int(mutCfg.csCapacity.Load())
}

// CfgSetCsCapacity sets the capacity of each forwarding thread's Content Store.
func CfgSetCsCapacity(capacity int) {
	mutCfg.csCapacity.Store(int32(capacity))
}

// CfgCsReplacementPolicy returns the replacement policy used by Content Stores in the forwarder.
func CfgCsReplacementPolicy() string {
	return core.C.Tables.ContentStore.ReplacementPolicy
}

// CfgDeadNonceListLifetime returns the lifetime of entries in the dead nonce list.
func CfgDeadNonceListLifetime() time.Duration {
	return time.Duration(core.C.Tables.DeadNonceList.Lifetime) * time.Millisecond
}
