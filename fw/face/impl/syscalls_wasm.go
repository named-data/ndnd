//go:build wasm

/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package impl

import (
	"syscall"
)

// (AI GENERATED DESCRIPTION): Sets the SO_REUSEADDR socket option on the supplied RawConn for the specified network address.
func SyscallReuseAddr(network string, address string, c syscall.RawConn) error {
	return nil
}

// (AI GENERATED DESCRIPTION): Returns the number of bytes currently queued in the send buffer of the socket represented by the given `syscall.RawConn`.
func SyscallGetSocketSendQueueSize(c syscall.RawConn) uint64 {
	return 0
}
