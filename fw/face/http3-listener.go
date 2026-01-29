//go:build !tinygo

package face

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// HTTP3ListenerConfig contains HTTP/3 WebTransport listener configuration.
type HTTP3ListenerConfig struct {
	Bind    string
	Port    uint16
	TLSCert string
	TLSKey  string
}

// (AI GENERATED DESCRIPTION): Builds and returns the listener’s network address string by combining its bind host and port into a properly formatted `host:port` string.
func (cfg HTTP3ListenerConfig) addr() string {
	return net.JoinHostPort(cfg.Bind, strconv.FormatUint(uint64(cfg.Port), 10))
}

// (AI GENERATED DESCRIPTION): Returns a `*url.URL` with scheme “https” and host set to the listener’s address.
func (cfg HTTP3ListenerConfig) URL() *url.URL {
	u := &url.URL{
		Scheme: "https",
		Host:   cfg.addr(),
	}
	return u
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable string that describes the HTTP3 listener configuration, showing its type and the URL it uses.
func (cfg HTTP3ListenerConfig) String() string {
	return fmt.Sprintf("http3-listener (url=%s)", cfg.URL())
}

// HTTP3Listener listens for incoming HTTP/3 WebTransport sessions.
type HTTP3Listener struct {
	mux    *http.ServeMux
	server *webtransport.Server
}

// (AI GENERATED DESCRIPTION): Creates a new HTTP/3 listener that loads the specified TLS credentials, registers a handler for the `/ndn` endpoint, and configures a WebTransport server to accept and serve incoming HTTP/3 connections.
func NewHTTP3Listener(cfg HTTP3ListenerConfig) (*HTTP3Listener, error) {
	l := &HTTP3Listener{}

	cert, e := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if e != nil {
		return nil, fmt.Errorf("tls.LoadX509KeyPair(%s %s): %w", cfg.TLSCert, cfg.TLSKey, e)
	}

	l.mux = http.NewServeMux()
	l.mux.HandleFunc("/ndn", l.handler)

	l.server = &webtransport.Server{
		H3: http3.Server{
			Addr: cfg.addr(),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
			QUICConfig: &quic.Config{
				MaxIdleTimeout:          60 * time.Second,
				KeepAlivePeriod:         30 * time.Second,
				DisablePathMTUDiscovery: true,
			},
			Handler: l.mux,
		},
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	return l, nil
}

// (AI GENERATED DESCRIPTION): Returns the literal string “HTTP/3 listener” as the textual representation of an HTTP/3 listener.
func (l *HTTP3Listener) String() string {
	return "HTTP/3 listener"
}

// (AI GENERATED DESCRIPTION): Runs the HTTP/3 listener, terminating the program with a fatal log if the server fails to start or stops unexpectedly (excluding the normal http.ErrServerClosed case).
func (l *HTTP3Listener) Run() {
	e := l.server.ListenAndServe()
	if !errors.Is(e, http.ErrServerClosed) {
		core.Log.Fatal(l, "Unable to start listener", "err", e)
	}
}

// (AI GENERATED DESCRIPTION): Handles an incoming HTTP/3 WebTransport upgrade, establishes an HTTP3Transport between the remote and local addresses, and launches an NDN link service on it with fragmentation enabled.
func (l *HTTP3Listener) handler(rw http.ResponseWriter, r *http.Request) {
	c, e := l.server.Upgrade(rw, r)
	if e != nil {
		return
	}

	remote, e := netip.ParseAddrPort(r.RemoteAddr)
	if e != nil {
		return
	}
	local, e := netip.ParseAddrPort(r.Context().Value(http.LocalAddrContextKey).(net.Addr).String())
	if e != nil {
		return
	}

	newTransport := NewHTTP3Transport(remote, local, c)
	core.Log.Info(l, "Accepting new HTTP/3 WebTransport face", "remote", r.RemoteAddr)

	options := MakeNDNLPLinkServiceOptions()
	options.IsFragmentationEnabled = true
	MakeNDNLPLinkService(newTransport, options).Run(nil)
}
