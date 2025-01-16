/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"os"
	"time"

	"github.com/named-data/ndnd/fw/core"
)

// Initialize initializes the face module.
func Initialize() {
	FaceTable.nextFaceID.Store(1)
	go FaceTable.expirationHandler()
}

// CfgFaceQueueSize returns the maximum number of packets that can be buffered
// to be sent or received on a face.
func CfgFaceQueueSize() int {
	return core.C.Faces.QueueSize
}

// CfgCongestionMarking returns whether congestion marking is enabled or disabled.
func CfgCongestionMarking() bool {
	return core.C.Faces.CongestionMarking
}

// CfgLockThreadsToCores returns whether face threads will be locked to logical cores.
func CfgLockThreadsToCores() bool {
	return core.C.Faces.LockThreadsToCores
}

// CfgUDPUnicastPort returns the configured unicast UDP port.
func CfgUDPUnicastPort() int {
	return int(core.C.Faces.Udp.PortUnicast)
}

// CfgUDPMulticastPort returns the configured multicast UDP port.
func CfgUDPMulticastPort() int {
	return int(core.C.Faces.Udp.PortMulticast)
}

// CfgUDP4MulticastAddress returns the configured multicast UDP4 address.
func CfgUDP4MulticastAddress() string {
	return core.C.Faces.Udp.MulticastAddressIpv4
}

// CfgUDP6MulticastAddress returns the configured multicast UDP6 address.
func CfgUDP6MulticastAddress() string {
	return core.C.Faces.Udp.MulticastAddressIpv6
}

// CfgUDPLifetime returns the lifetime of on-demand UDP faces after they become idle.
func CfgUDPLifetime() time.Duration {
	return time.Duration(core.C.Faces.Udp.Lifetime) * time.Second
}

// CfgTCPUnicastPort returns the configured unicast TCP port.
func CfgTCPUnicastPort() int {
	return int(core.C.Faces.Tcp.PortUnicast)
}

// CfgTCPLifetime returns the lifetime of on-demand TCP faces after they become idle.
func CfgTCPLifetime() time.Duration {
	return time.Duration(core.C.Faces.Tcp.Lifetime) * time.Second
}

// CfgUnixSocketPath returns the configured Unix socket file path.
func CfgUnixSocketPath() string {
	return os.ExpandEnv(core.C.Faces.Unix.SocketPath)
}
