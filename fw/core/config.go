/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package core

import (
	"path/filepath"
	"runtime"
)

// Global initial configuration of the forwarder.
// This configuration is IMMUTABLE. Do not modify it.
var C = DefaultConfig()

// Config represents the configuration of the forwarder.
type Config struct {
	Core struct {
		// Logging level
		LogLevel string `json:"log_level"`
		// Output log to file
		LogFile string `json:"log_file"`

		// Config file base dir
		BaseDir string `json:"-"`
		// Enable CPU profiling
		CpuProfile string `json:"-"`
		// Enable memory profiling
		MemProfile string `json:"-"`
		// Enable block profiling
		BlockProfile string `json:"-"`
	} `json:"core"`

	Faces struct {
		// Size of queues in the face system
		QueueSize int `json:"queue_size"`
		// Enables or disables congestion marking
		CongestionMarking bool `json:"congestion_marking"`
		// If true, face threads will be locked to processor cores
		LockThreadsToCores bool `json:"lock_threads_to_cores"`

		Udp struct {
			// Whether to enable unicast UDP listener
			EnabledUnicast bool `json:"enabled_unicast"`
			// Whether to enable multicast UDP listener
			EnabledMulticast bool `json:"enabled_multicast"`
			// Port used for unicast UDP faces
			PortUnicast uint16 `json:"port_unicast"`
			// Port used for multicast UDP faces
			PortMulticast uint16 `json:"port_multicast"`
			// IPv4 address used for multicast UDP faces
			MulticastAddressIpv4 string `json:"multicast_address_ipv4"`
			// IPv6 address used for multicast UDP faces
			MulticastAddressIpv6 string `json:"multicast_address_ipv6"`
			// Lifetime of on-demand faces (in seconds)
			Lifetime uint64 `json:"lifetime"`
			// Default MTU for UDP faces
			DefaultMtu uint16 `json:"default_mtu"`
		} `json:"udp"`

		Tcp struct {
			// Whether to enable TCP listener
			Enabled bool `json:"enabled"`
			// Port used for unicast TCP faces
			PortUnicast uint16 `json:"port_unicast"`
			// Lifetime of on-demand faces (in seconds)
			Lifetime uint64 `json:"lifetime"`
			// Reconnect interval for permanent faces (in seconds)
			ReconnectInterval uint64 `json:"reconnect_interval"`
		} `json:"tcp"`

		Unix struct {
			// Whether to enable Unix stream transports
			Enabled bool `json:"enabled"`
			// Location of the socket file
			SocketPath string `json:"socket_path"`
		} `json:"unix"`

		WebSocket struct {
			// Whether to enable WebSocket listener
			Enabled bool `json:"enabled"`
			// Bind address for WebSocket listener
			Bind string `json:"bind"`
			// Port for WebSocket listener
			Port uint16 `json:"port"`
			// Whether to enable TLS
			TlsEnabled bool `json:"tls_enabled"`
			// TLS certificate path (relative to the config file)
			TlsCert string `json:"tls_cert"`
			// TLS private key (relative to the config file)
			TlsKey string `json:"tls_key"`
		} `json:"websocket"`

		HTTP3 struct {
			// Whether to enable HTTP/3 WebTransport listener
			Enabled bool `json:"enabled"`
			// Bind address for HTTP/3 WebTransport listener
			Bind string `json:"bind"`
			// Port for HTTP/3 WebTransport listener
			Port uint16 `json:"port"`
			// TLS certificate path (relative to the config file)
			TlsCert string `json:"tls_cert"`
			// TLS private key (relative to the config file)
			TlsKey string `json:"tls_key"`
		} `json:"http3"`
	} `json:"faces"`

	Fw struct {
		// Number of forwarding threads
		Threads int `json:"threads"`
		// Size of queues in the forwarding system
		QueueSize int `json:"queue_size"`
		// If true, face threads will be locked to processor cores
		LockThreadsToCores bool `json:"lock_threads_to_cores"`
	} `json:"fw"`

	Mgmt struct {
		// Controls whether management over /localhop is enabled or disabled
		AllowLocalhop bool `json:"allow_localhop"`
	} `json:"mgmt"`

	Tables struct {
		ContentStore struct {
			// Capacity of each forwarding thread's content store (in number of Data packets). Note that the
			// total capacity of all content stores in the forwarder will be the number of threads
			// multiplied by this value. This is the startup configuration value and can be changed at
			// runtime via management.
			Capacity uint16 `json:"capacity"`
			// Whether contents will be admitted to the Content Store.
			Admit bool `json:"admit"`
			// Whether contents will be served from the Content Store.
			Serve bool `json:"serve"`
			// Cache replacement policy to use in each thread's content store.
			ReplacementPolicy string `json:"replacement_policy"`
		} `json:"content_store"`

		DeadNonceList struct {
			// Lifetime of entries in the Dead Nonce List (milliseconds)
			Lifetime int `json:"lifetime"`
		} `json:"dead_nonce_list"`

		NetworkRegion struct {
			// List of prefixes that the forwarder is in the producer region for
			Regions []string `json:"regions"`
		} `json:"network_region"`

		Rib struct {
			// Enables or disables readvertising to the routing daemon
			ReadvertiseNlsr bool `json:"readvertise_nlsr"`
		} `json:"rib"`

		Fib struct {
			// Selects the algorithm used to implement the FIB
			// Allowed options: nametree, hashtable
			Algorithm string `json:"algorithm"`

			Hashtable struct {
				// Specifies the virtual node depth. Must be a positive number.
				M uint16 `json:"m"`
			} `json:"hashtable"`
		} `json:"fib"`
	} `json:"tables"`
}

// (AI GENERATED DESCRIPTION): Creates and returns a `Config` object pre‑populated with default settings for core parameters, face types, forwarding, management, and table options.
func DefaultConfig() *Config {
	c := &Config{}
	c.Core.LogLevel = "INFO"
	c.Core.LogFile = ""

	c.Core.BaseDir = ""
	c.Core.CpuProfile = ""
	c.Core.MemProfile = ""
	c.Core.BlockProfile = ""

	c.Faces.QueueSize = 1024
	c.Faces.CongestionMarking = true
	c.Faces.LockThreadsToCores = false

	c.Faces.Udp.EnabledUnicast = true
	c.Faces.Udp.EnabledMulticast = true
	c.Faces.Udp.PortUnicast = 6363
	c.Faces.Udp.PortMulticast = 56363
	c.Faces.Udp.MulticastAddressIpv4 = "224.0.23.170"
	c.Faces.Udp.MulticastAddressIpv6 = "ff02::114"
	c.Faces.Udp.Lifetime = 600
	c.Faces.Udp.DefaultMtu = 1420

	c.Faces.Tcp.Enabled = true
	c.Faces.Tcp.PortUnicast = 6363
	c.Faces.Tcp.Lifetime = 600
	c.Faces.Tcp.ReconnectInterval = 10

	c.Faces.Unix.Enabled = true
	c.Faces.Unix.SocketPath = "/run/nfd/nfd.sock"
	if runtime.GOOS == "darwin" {
		c.Faces.Unix.SocketPath = "/var/run/nfd/nfd.sock"
	}

	c.Faces.WebSocket.Enabled = true
	c.Faces.WebSocket.Bind = ""
	c.Faces.WebSocket.Port = 9696
	c.Faces.WebSocket.TlsEnabled = false
	c.Faces.WebSocket.TlsCert = ""
	c.Faces.WebSocket.TlsKey = ""

	c.Faces.HTTP3.Enabled = false
	c.Faces.HTTP3.Bind = ""
	c.Faces.HTTP3.Port = 443
	c.Faces.HTTP3.TlsCert = ""
	c.Faces.HTTP3.TlsKey = ""

	c.Fw.Threads = 8
	c.Fw.QueueSize = 1024
	c.Fw.LockThreadsToCores = false

	c.Mgmt.AllowLocalhop = false

	c.Tables.ContentStore.Capacity = 1024
	c.Tables.ContentStore.Admit = true
	c.Tables.ContentStore.Serve = true
	c.Tables.ContentStore.ReplacementPolicy = "lru"

	c.Tables.DeadNonceList.Lifetime = 6000
	c.Tables.NetworkRegion.Regions = []string{}
	c.Tables.Rib.ReadvertiseNlsr = true

	c.Tables.Fib.Algorithm = "nametree"
	c.Tables.Fib.Hashtable.M = 5

	return c
}

// ResolveRelPath resolves a possibly relative path based on config file path.
func (c *Config) ResolveRelPath(target string) string {
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(c.Core.BaseDir, target)
}
