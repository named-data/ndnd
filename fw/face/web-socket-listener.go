/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

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

func (cfg WebSocketListenerConfig) String() string {
	return fmt.Sprintf("web-socket-listener (url=%s tls=%s)", cfg.URL(), cfg.TLSCert)
}

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

func (l *WebSocketListener) String() string {
	return "WebSocketListener, " + l.localURI.String()
}

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

func (l *WebSocketListener) Close() {
	core.Log.Info(l, "Stopping listener")
	l.server.Shutdown(context.TODO())
}
