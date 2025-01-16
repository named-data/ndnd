/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import "github.com/named-data/ndnd/fw/core"

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
