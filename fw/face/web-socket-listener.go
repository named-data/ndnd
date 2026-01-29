//go:build !tinygo

package face

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
)

// WebSocketListenerConfig contains WebSocketListener configuration.
type WebSocketListenerConfig struct {
	Bind       string
	Port       uint16
	TLSEnabled bool
	TLSCert    string
	TLSKey     string
}

// WebSocketListener listens for incoming WebSockets connections.
type WebSocketListener struct {
	server   http.Server
	upgrader websocket.Upgrader
	localURI *defn.URI
}

// (AI GENERATED DESCRIPTION): Generates a *url.URL for a WebSocket listener by joining the bind address and port, and selecting the scheme “ws” or “wss” based on the TLS enabled flag.
func (cfg WebSocketListenerConfig) URL() *url.URL {
	addr := net.JoinHostPort(cfg.Bind, strconv.FormatUint(uint64(cfg.Port), 10))
	u := &url.URL{
		Scheme: "ws",
		Host:   addr,
	}
	if cfg.TLSEnabled {
		u.Scheme = "wss"
	}
	return u
}

// (AI GENERATED DESCRIPTION): Returns a string describing the WebSocketListenerConfig, showing its URL and TLS certificate path.
func (cfg WebSocketListenerConfig) String() string {
	return fmt.Sprintf("web-socket-listener (url=%s tls=%s)", cfg.URL(), cfg.TLSCert)
}

// (AI GENERATED DESCRIPTION): Creates a WebSocketListener configured with the given URL and TLS options, initializing its HTTP server, upgrader, and local URI for the listener.
func NewWebSocketListener(cfg WebSocketListenerConfig) (*WebSocketListener, error) {
	localURI := cfg.URL()
	ret := &WebSocketListener{
		server: http.Server{Addr: localURI.Host},
		upgrader: websocket.Upgrader{
			WriteBufferPool: &sync.Pool{},
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
		localURI: defn.MakeWebSocketServerFaceURI(localURI),
	}
	if cfg.TLSEnabled {
		cert, e := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if e != nil {
			return nil, fmt.Errorf("tls.LoadX509KeyPair(%s %s): %w", cfg.TLSCert, cfg.TLSKey, e)
		}
		ret.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		localURI.Scheme = "wss"
	}
	return ret, nil
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable description of the WebSocketListener, including its type and local URI.
func (l *WebSocketListener) String() string {
	return "WebSocketListener, " + l.localURI.String()
}

// (AI GENERATED DESCRIPTION): Starts the WebSocket listener by assigning its handler to the HTTP server and invoking ListenAndServe (or ListenAndServeTLS if TLS is configured), logging a fatal error unless the failure is due to a normal server shutdown.
func (l *WebSocketListener) Run() {
	l.server.Handler = http.HandlerFunc(l.handler)

	var err error
	if l.server.TLSConfig == nil {
		err = l.server.ListenAndServe()
	} else {
		err = l.server.ListenAndServeTLS("", "")
	}
	if !errors.Is(err, http.ErrServerClosed) {
		core.Log.Fatal(l, "Unable to start listener", "err", err)
	}
}

// (AI GENERATED DESCRIPTION): Upgrades an HTTP request to a WebSocket, creates a transport for it, logs the new face, and starts a reliable NDN‑LP link service over the connection.
func (l *WebSocketListener) handler(w http.ResponseWriter, r *http.Request) {
	c, e := l.upgrader.Upgrade(w, r, nil)
	if e != nil {
		return
	}

	newTransport := NewWebSocketTransport(l.localURI, c)
	core.Log.Info(l, "Accepting new WebSocket face", "uri", newTransport.RemoteURI())

	options := MakeNDNLPLinkServiceOptions()
	options.IsFragmentationEnabled = false // reliable stream
	MakeNDNLPLinkService(newTransport, options).Run(nil)
}

// (AI GENERATED DESCRIPTION): Stops the WebSocket listener by shutting down its underlying HTTP server and logs the stopping action.
func (l *WebSocketListener) Close() {
	core.Log.Info(l, "Stopping listener")
	l.server.Shutdown(context.TODO())
}
