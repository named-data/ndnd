/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package defn

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// URIType represents the type of the URI.
type URIType int

// Regex to extract zone from URI.
// Windows zones can have spaces in them.
var zoneRegex, _ = regexp.Compile(`:\/\/\[?(?:[0-9A-Za-z\:\.\-]+)(?:%(?P<zone>[A-Za-z0-9 \-]+))?\]?`)

// URL not canonical error
var ErrNotCanonical = errors.New("URI could not be canonized")

const (
	unknownURI URIType = iota
	devURI
	fdURI
	internalURI
	nullURI
	udpURI
	tcpURI
	unixURI
	wsURI
	wsclientURI
	quicURI
)

// URI represents a URI for a face.
type URI struct {
	uriType URIType
	scheme  string
	path    string
	port    uint16
}

// MakeDevFaceURI constucts a URI for a network interface.
func MakeDevFaceURI(ifname string) *URI {
	uri := new(URI)
	uri.uriType = devURI
	uri.scheme = "dev"
	uri.path = ifname
	uri.port = 0
	uri.Canonize()
	return uri
}

// MakeFDFaceURI constructs a file descriptor URI.
func MakeFDFaceURI(fd int) *URI {
	uri := new(URI)
	uri.uriType = fdURI
	uri.scheme = "fd"
	uri.path = strconv.Itoa(fd)
	uri.port = 0
	uri.Canonize()
	return uri
}

// MakeInternalFaceURI constructs an internal face URI.
func MakeInternalFaceURI() *URI {
	uri := new(URI)
	uri.uriType = internalURI
	uri.scheme = "internal"
	uri.path = ""
	uri.port = 0
	return uri
}

// MakeNullFaceURI constructs a null face URI.
func MakeNullFaceURI() *URI {
	uri := new(URI)
	uri.uriType = nullURI
	uri.scheme = "null"
	uri.path = ""
	uri.port = 0
	uri.Canonize()
	return uri
}

// MakeUDPFaceURI constructs a URI for a UDP face.
func MakeUDPFaceURI(ipVersion int, host string, port uint16) *URI {
	uri := new(URI)
	uri.uriType = udpURI
	uri.scheme = "udp" + strconv.Itoa(ipVersion)
	uri.path = host
	uri.port = port
	uri.Canonize()
	return uri
}

// MakeTCPFaceURI constructs a URI for a TCP face.
func MakeTCPFaceURI(ipVersion int, host string, port uint16) *URI {
	uri := new(URI)
	uri.uriType = tcpURI
	uri.scheme = "tcp" + strconv.Itoa(ipVersion)
	uri.path = host
	uri.port = port
	uri.Canonize()
	return uri
}

// MakeUnixFaceURI constructs a URI for a Unix face.
func MakeUnixFaceURI(path string) *URI {
	uri := new(URI)
	uri.uriType = unixURI
	uri.scheme = "unix"
	uri.path = path
	uri.port = 0
	uri.Canonize()
	return uri
}

// MakeWebSocketServerFaceURI constructs a URI for a WebSocket server.
func MakeWebSocketServerFaceURI(u *url.URL) *URI {
	port, _ := strconv.ParseUint(u.Port(), 10, 16)
	return &URI{
		uriType: wsURI,
		scheme:  u.Scheme,
		path:    u.Hostname(),
		port:    uint16(port),
	}
}

// MakeWebSocketClientFaceURI constructs a URI for a WebSocket server.
func MakeWebSocketClientFaceURI(addr net.Addr) *URI {
	host, portStr, _ := net.SplitHostPort(addr.String())
	port, _ := strconv.ParseUint(portStr, 10, 16)
	return &URI{
		uriType: wsclientURI,
		scheme:  "wsclient",
		path:    host,
		port:    uint16(port),
	}
}

// MakeQuicFaceURI constructs a URI for an HTTP/3 WebTransport endpoint.
func MakeQuicFaceURI(addr netip.AddrPort) *URI {
	return &URI{
		uriType: quicURI,
		scheme:  "quic",
		path:    addr.Addr().String(),
		port:    addr.Port(),
	}
}

// (AI GENERATED DESCRIPTION): Parses a URI string into a normalized URI object, interpreting its scheme, host, port, path, and optional zone, handling special cases (dev, fd, internal, null, unix, WebSocket server/client) and returning the resulting URI or nil on failure.
func DecodeURIString(str string) *URI {
	ret := &URI{
		uriType: unknownURI,
		scheme:  "unknown",
	}

	// extract zone if present first, since this is non-standard
	var zone string = ""
	zoneMatch := zoneRegex.FindStringSubmatch(str)
	if len(zoneMatch) > zoneRegex.SubexpIndex("zone") {
		zone = zoneMatch[zoneRegex.SubexpIndex("zone")]
		str = strings.Replace(str, "%"+zone, "", 1)
	}

	// parse common URI schemes
	uri, err := url.Parse(str)
	if err != nil {
		return ret
	}

	decodeHostPort := func(uriType URIType, defaultPort uint16) {
		ret.uriType = uriType

		ret.scheme = uri.Scheme
		ret.path = uri.Hostname()
		if uri.Port() != "" {
			port, _ := strconv.ParseUint(uri.Port(), 10, 16)
			ret.port = uint16(port)
		} else {
			ret.port = uint16(6363) // default NDN port
		}

		if zone != "" {
			ret.path += "%" + zone
		}
	}

	switch uri.Scheme {
	case "dev":
		ret.uriType = devURI
		ret.scheme = uri.Scheme
		ret.path = uri.Host
	case "fd":
		ret.uriType = fdURI
		ret.scheme = uri.Scheme
		ret.path = uri.Host
	case "internal":
		ret.uriType = internalURI
		ret.scheme = uri.Scheme
	case "null":
		ret.uriType = nullURI
		ret.scheme = uri.Scheme
	case "udp", "udp4", "udp6":
		decodeHostPort(udpURI, 6363)
	case "tcp", "tcp4", "tcp6":
		decodeHostPort(tcpURI, 6363)
	case "quic":
		decodeHostPort(quicURI, 443)
	case "unix":
		ret.uriType = unixURI
		ret.scheme = uri.Scheme
		ret.path = uri.Path
	case "ws", "wss":
		if uri.User != nil || strings.TrimLeft(uri.Path, "/") != "" || uri.RawQuery != "" || uri.Fragment != "" {
			return nil
		}
		return MakeWebSocketServerFaceURI(uri)
	case "wsclient":
		addr, err := net.ResolveTCPAddr("tcp", uri.Host)
		if err != nil {
			return nil
		}
		return MakeWebSocketClientFaceURI(addr)
	}

	ret.Canonize()

	return ret
}

// URIType returns the type of the face URI.
func (u *URI) URIType() URIType {
	return u.uriType
}

// Scheme returns the scheme of the face URI.
func (u *URI) Scheme() string {
	return u.scheme
}

// Path returns the path of the face URI.
func (u *URI) Path() string {
	return u.path
}

// PathHost returns the host component of the path of the face URI.
func (u *URI) PathHost() string {
	pathComponents := strings.Split(u.path, "%")
	if len(pathComponents) < 1 {
		return ""
	}
	return pathComponents[0]
}

// PathZone returns the zone component of the path of the face URI.
func (u *URI) PathZone() string {
	pathComponents := strings.Split(u.path, "%")
	if len(pathComponents) < 2 {
		return ""
	}
	return pathComponents[1]
}

// Port returns the port of the face URI.
func (u *URI) Port() uint16 {
	return u.port
}

// IsCanonical returns whether the face URI is canonical.
func (u *URI) IsCanonical() bool {
	// Must pass type-specific checks
	switch u.uriType {
	case devURI:
		return u.scheme == "dev" && u.path != "" && u.port == 0
	case fdURI:
		fd, err := strconv.Atoi(u.path)
		return u.scheme == "fd" && err == nil && fd >= 0 && u.port == 0
	case internalURI:
		return u.scheme == "internal" && u.path == "" && u.port == 0
	case nullURI:
		return u.scheme == "null" && u.path == "" && u.port == 0
	case udpURI:
		// Split off zone, if any
		ip := net.ParseIP(u.PathHost())
		// Port number is implicitly limited to <= 65535 by type uint16
		// We have to test whether To16() && not IPv4 because the Go net library considers IPv4 addresses to be valid IPv6 addresses
		isIPv4 := ip.To4() != nil
		return ip != nil && ((u.scheme == "udp4" && isIPv4) ||
			(u.scheme == "udp6" && ip.To16() != nil && !isIPv4)) && u.port > 0
	case tcpURI:
		// Split off zone, if any
		ip := net.ParseIP(u.PathHost())
		// Port number is implicitly limited to <= 65535 by type uint16
		// We have to test whether To16() && not IPv4 because the Go net library considers IPv4 addresses to be valid IPv6 addresses
		isIPv4 := ip.To4() != nil
		return ip != nil && u.port > 0 && ((u.scheme == "tcp4" && ip.To4() != nil) ||
			(u.scheme == "tcp6" && ip.To16() != nil && !isIPv4))
	case unixURI:
		// Do not check whether file exists, because it may fail due to lack of privilege in testing environment
		return u.scheme == "unix" && u.path != "" && u.port == 0
	default:
		// Of unknown type
		return false
	}
}

// Canonize attempts to canonize the URI, if not already canonical.
func (u *URI) Canonize() error {
	switch u.uriType {
	case devURI, fdURI:
		// Nothing to do to canonize these
	case udpURI, tcpURI:
		path := u.path
		zone := ""
		if strings.Contains(u.path, "%") {
			// Has zone, so separate out
			path = u.PathHost()
			zone = "%" + u.PathZone()
		}
		ip := net.ParseIP(strings.Trim(path, "[]"))
		if ip == nil {
			// Resolve DNS
			resolvedIPs, err := net.LookupHost(path)
			if err != nil || len(resolvedIPs) == 0 {
				return ErrNotCanonical
			}
			ip = net.ParseIP(resolvedIPs[0])
			if ip == nil {
				return ErrNotCanonical
			}
		}

		if ip.To4() != nil {
			if u.uriType == udpURI {
				u.scheme = "udp4"
			} else {
				u.scheme = "tcp4"
			}
			u.path = ip.String() + zone
		} else if ip.To16() != nil {
			if u.uriType == udpURI {
				u.scheme = "udp6"
			} else {
				u.scheme = "tcp6"
			}
			u.path = ip.String() + zone
		} else {
			return ErrNotCanonical
		}
	case unixURI:
		u.scheme = "unix"
		testPath := "/" + u.path
		if runtime.GOOS == "windows" {
			testPath = u.path
		}
		fileInfo, err := os.Stat(testPath)
		if err != nil && !os.IsNotExist(err) {
			// File couldn't be opened, but not just because it doesn't exist
			return ErrNotCanonical
		} else if err == nil && fileInfo.IsDir() {
			// File is a directory
			return ErrNotCanonical
		}
		u.port = 0
	default:
		return ErrNotCanonical
	}

	return nil
}

// Scope returns the scope of the URI.
func (u *URI) Scope() Scope {
	if !u.IsCanonical() {
		return Unknown
	}

	switch u.uriType {
	case devURI:
		return NonLocal
	case fdURI:
		return Local
	case nullURI:
		return NonLocal
	case udpURI:
		if net.ParseIP(u.path).IsLoopback() {
			return Local
		}
		return NonLocal
	case unixURI:
		return Local
	}

	// Only valid types left is internal, which is by definition local
	return Local
}

// (AI GENERATED DESCRIPTION): Formats a URI object into its canonical string representation based on its type, scheme, host, port, and path.
func (u *URI) String() string {
	switch u.uriType {
	case devURI:
		return "dev://" + u.path
	case fdURI:
		return "fd://" + u.path
	case internalURI:
		return "internal://"
	case nullURI:
		return "null://"
	case udpURI, tcpURI, wsURI, wsclientURI, quicURI:
		return u.scheme + "://" + net.JoinHostPort(u.path, strconv.FormatUint(uint64(u.port), 10))
	case unixURI:
		return u.scheme + "://" + u.path
	default:
		return "unknown://"
	}
}
