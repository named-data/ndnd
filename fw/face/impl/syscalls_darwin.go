//go:build darwin

/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package impl

import (
	"syscall"

	"github.com/named-data/ndnd/fw/core"
	"golang.org/x/sys/unix"
)

// SyscallGetSocketSendQueueSize returns the current size of the send queue on the specified socket.
func SyscallGetSocketSendQueueSize(c syscall.RawConn) uint64 {
	var val int
	c.Control(func(fd uintptr) {
		var err error
		val, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_NWRITE)
		if err != nil {
			core.Log.Warn(nil, "Unable to get size of socket send queue for fd", "fd", fd, "err", err)
			val = 0
		}
	})
	return uint64(val)
}
