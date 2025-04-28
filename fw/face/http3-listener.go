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

func (cfg HTTP3ListenerConfig) addr() string {
	return net.JoinHostPort(cfg.Bind, strconv.FormatUint(uint64(cfg.Port), 10))
}

func (cfg HTTP3ListenerConfig) URL() *url.URL {
	u := &url.URL{
		Scheme: "https",
		Host:   cfg.addr(),
	}
	return u
}

func (cfg HTTP3ListenerConfig) String() string {
	return fmt.Sprintf("http3-listener (url=%s)", cfg.URL())
}

// HTTP3Listener listens for incoming HTTP/3 WebTransport sessions.
type HTTP3Listener struct {
	mux    *http.ServeMux
	server *webtransport.Server
}

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

func (l *HTTP3Listener) String() string {
	return "HTTP/3 listener"
}

func (l *HTTP3Listener) Run() {
	e := l.server.ListenAndServe()
	if !errors.Is(e, http.ErrServerClosed) {
		core.Log.Fatal(l, "Unable to start listener", "err", e)
	}
}

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
