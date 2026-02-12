/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import (
	"sync"

	"github.com/named-data/ndnd/fw/core"
	enc "github.com/named-data/ndnd/std/encoding"
)

// FwQueueSize is the maxmimum number of packets that can be buffered to be processed by a forwarding thread.
func CfgFwQueueSize() int {
	return core.C.Fw.QueueSize
}

// NumFwThreads indicates the number of forwarding threads in the forwarder.
func CfgNumThreads() int {
	return core.C.Fw.Threads
}

// LockThreadsToCores indicates whether forwarding threads will be locked to cores.
func CfgLockThreadsToCores() bool {
	return core.C.Fw.LockThreadsToCores
}

var routerNameCache struct {
	once sync.Once
	name enc.Name
	ok   bool
}

// CfgRouterName returns the configured router name as an enc.Name.
func CfgRouterName() (enc.Name, bool) {
	routerNameCache.once.Do(func() {
		if core.C.Fw.RouterName == "" {
			return
		}
		name, err := enc.NameFromStr(core.C.Fw.RouterName)
		if err != nil {
			core.Log.Warn(nil, "Invalid router_name in forwarder config", "name", core.C.Fw.RouterName, "err", err)
			return
		}
		routerNameCache.name = name
		routerNameCache.ok = true
	})
	return routerNameCache.name, routerNameCache.ok
}
