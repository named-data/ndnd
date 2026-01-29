/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
)

// UnixStreamListener listens for incoming Unix stream connections.
type UnixStreamListener struct {
	conn     net.Listener
	localURI *defn.URI
	nextFD   int // We can't (at least easily) access the actual FD through net.Conn, so we'll make our own
	stopped  chan bool
}

// MakeUnixStreamListener constructs a UnixStreamListener.
func MakeUnixStreamListener(localURI *defn.URI) (*UnixStreamListener, error) {
	localURI.Canonize()
	if !localURI.IsCanonical() || localURI.Scheme() != "unix" {
		return nil, defn.ErrNotCanonical
	}

	return &UnixStreamListener{
		localURI: localURI,
		nextFD:   1,
		stopped:  make(chan bool, 1),
	}, nil
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable string identifying the UnixStreamListener, including its local URI.
func (l *UnixStreamListener) String() string {
	return fmt.Sprintf("unix-stream-listener (%s)", l.localURI)
}

// (AI GENERATED DESCRIPTION): Runs a Unix‑domain socket listener that accepts incoming stream connections, creates an NDN link service for each connection, and starts it until the program exits.
func (l *UnixStreamListener) Run() {
	defer func() { l.stopped <- true }()

	// Delete any existing socket
	os.Remove(l.localURI.Path())

	// Create inside folder if not existing
	sockPath := l.localURI.Path()
	dirPath := path.Dir(sockPath)
	os.MkdirAll(dirPath, os.ModePerm)

	// Create listener
	var err error
	if l.conn, err = net.Listen(l.localURI.Scheme(), sockPath); err != nil {
		core.Log.Fatal(l, "Unable to start Unix stream listener", "err", err)
	}

	// Set permissions to allow all local apps to communicate with us
	if err := os.Chmod(sockPath, os.ModePerm); err != nil {
		core.Log.Fatal(l, "Unable to change permissions on Unix stream listener", "err", err)
	}

	core.Log.Info(l, "Listening for connections")

	// Run accept loop
	for !core.ShouldQuit {
		newConn, err := l.conn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			core.Log.Warn(l, "Unable to accept connection", "err", err)
			return
		}

		remoteURI := defn.MakeFDFaceURI(l.nextFD)
		l.nextFD++
		if !remoteURI.IsCanonical() {
			core.Log.Warn(l, "Unable to create face remote URI is not canonical", "uri", remoteURI)
			continue
		}

		newTransport, err := MakeUnixStreamTransport(remoteURI, l.localURI, newConn)
		if err != nil {
			core.Log.Error(l, "Failed to create new unix stream transport", "err", err)
			continue
		}

		core.Log.Info(l, "Accepting new unix stream face", "uri", remoteURI)
		options := MakeNDNLPLinkServiceOptions()
		options.IsFragmentationEnabled = false // reliable stream
		MakeNDNLPLinkService(newTransport, options).Run(nil)
	}
}

// (AI GENERATED DESCRIPTION): Closes the listener’s underlying connection if it exists and blocks until the listener’s stopped channel signals that it has fully stopped.
func (l *UnixStreamListener) Close() {
	if l.conn != nil {
		l.conn.Close()
		<-l.stopped
	}
}
