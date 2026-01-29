package defn_test

import (
	"strings"
	"testing"

	"github.com/named-data/ndnd/fw/defn"
	"github.com/stretchr/testify/assert"
)

// (AI GENERATED DESCRIPTION): Verifies that `DecodeURIString` correctly parses diverse URI strings, extracting scheme, host, port, zone, and correctly marking canonical versus non‑canonical forms.
func TestDecodeUri(t *testing.T) {
	var uri *defn.URI

	// Unknown URI
	uri = defn.DecodeURIString("test://myhost:1234")
	assert.False(t, uri.IsCanonical())
	assert.Equal(t, "unknown", uri.Scheme())

	// Device URI
	uri = defn.DecodeURIString("dev://eth0")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "dev", uri.Scheme())
	assert.Equal(t, "eth0", uri.PathHost())

	// FD URI
	uri = defn.DecodeURIString("fd://3")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "fd", uri.Scheme())
	assert.Equal(t, "3", uri.PathHost())

	// Internal URI
	uri = defn.DecodeURIString("internal://")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "internal", uri.Scheme())

	// NULL URI
	uri = defn.DecodeURIString("null://")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "null", uri.Scheme())

	// Unix URI
	uri = defn.DecodeURIString("unix:///tmp/test.sock")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "unix", uri.Scheme())
	assert.Equal(t, "/tmp/test.sock", uri.PathHost())
	assert.Equal(t, uint16(0), uri.Port())

	// UDP URI
	uri = defn.DecodeURIString("udp://127.0.0.1:5000")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "udp4", uri.Scheme())
	assert.Equal(t, "127.0.0.1", uri.PathHost())
	assert.Equal(t, uint16(5000), uri.Port())

	uri = defn.DecodeURIString("udp://[2001:db8::1]:5000")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "udp6", uri.Scheme())
	assert.Equal(t, "2001:db8::1", uri.PathHost())
	assert.Equal(t, uint16(5000), uri.Port())

	// TCP URI
	uri = defn.DecodeURIString("tcp://127.0.0.1:4600")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "tcp4", uri.Scheme())
	assert.Equal(t, "127.0.0.1", uri.PathHost())
	assert.Equal(t, uint16(4600), uri.Port())

	uri = defn.DecodeURIString("tcp://[2002:db8::1]:4600")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "tcp6", uri.Scheme())
	assert.Equal(t, "2002:db8::1", uri.PathHost())
	assert.Equal(t, uint16(4600), uri.Port())

	// Ws URI (server)
	uri = defn.DecodeURIString("ws://0.0.0.0:5000")
	assert.False(t, uri.IsCanonical())
	assert.Equal(t, "ws", uri.Scheme())
	assert.Equal(t, uint16(5000), uri.Port())

	// Ws URI (client)
	uri = defn.DecodeURIString("wsclient://127.0.0.1:800")
	assert.False(t, uri.IsCanonical())
	assert.Equal(t, "wsclient", uri.Scheme())
	assert.Equal(t, "127.0.0.1", uri.PathHost())
	assert.Equal(t, uint16(800), uri.Port())

	// QUIC URI
	uri = defn.DecodeURIString("quic://[::1]:443")
	assert.False(t, uri.IsCanonical())
	assert.Equal(t, "quic", uri.Scheme())
	assert.Equal(t, uint16(443), uri.Port())

	// UDP4 with zone
	uri = defn.DecodeURIString("udp://127.0.0.1%eth0:3000")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "udp4", uri.Scheme())
	assert.Equal(t, "127.0.0.1", uri.PathHost())
	assert.Equal(t, "127.0.0.1%eth0", uri.Path())
	assert.Equal(t, "eth0", uri.PathZone())
	assert.Equal(t, uint16(3000), uri.Port())

	// UDP6 with zone
	uri = defn.DecodeURIString("udp://[2001:db8::1%eth0]:3000")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "udp6", uri.Scheme())
	assert.Equal(t, "2001:db8::1", uri.PathHost())
	assert.Equal(t, "2001:db8::1%eth0", uri.Path())
	assert.Equal(t, "eth0", uri.PathZone())
	assert.Equal(t, uint16(3000), uri.Port())

	// Test name resolution for IPv4 and IPv6
	uri = defn.DecodeURIString("udp://ipv4.google.com:5000")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "udp4", uri.Scheme())
	assert.Equal(t, 3, strings.Count(uri.PathHost(), "."))
	assert.Equal(t, uint16(5000), uri.Port())

	uri = defn.DecodeURIString("udp://ipv6.google.com:5000")
	assert.True(t, uri.IsCanonical())
	assert.Equal(t, "udp6", uri.Scheme())
	assert.Equal(t, uint16(5000), uri.Port())
}
