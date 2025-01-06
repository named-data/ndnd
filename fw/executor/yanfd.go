/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package executor

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/face"
	"github.com/named-data/ndnd/fw/fw"
	"github.com/named-data/ndnd/fw/mgmt"
	"github.com/named-data/ndnd/fw/table"
)

// YaNFDConfig is the configuration of YaNFD.
type YaNFDConfig struct {
	Version string
	LogFile string

	Config  *core.Config
	BaseDir string

	CpuProfile        string
	MemProfile        string
	BlockProfile      string
	MemoryBallastSize int
}

// YaNFD is the wrapper class for the NDN Forwarding Daemon.
// Note: only one instance of this class should be created.
type YaNFD struct {
	config   *YaNFDConfig
	profiler *Profiler

	unixListener *face.UnixStreamListener
	wsListener   *face.WebSocketListener
	tcpListeners []*face.TCPListener
	udpListeners []*face.UDPListener
}

func (y *YaNFD) String() string {
	return "YaNFD"
}

// NewYaNFD creates a YaNFD. Don't call this function twice.
func NewYaNFD(config *YaNFDConfig) *YaNFD {
	// Provide metadata to other threads.
	core.Version = config.Version
	core.StartTimestamp = time.Now()

	// Allocate memory ballast (if enabled)
	if config.MemoryBallastSize > 0 {
		_ = make([]byte, config.MemoryBallastSize<<30)
	}

	// Initialize config file
	core.LoadConfig(config.Config, config.BaseDir)
	core.InitializeLogger(config.LogFile)
	face.Configure()
	fw.Configure()
	table.Configure()
	mgmt.Configure()

	return &YaNFD{
		config:   config,
		profiler: NewProfiler(config),
	}
}

// Start runs YaNFD. Note: this function may exit the program when there is error.
// This function is non-blocking.
func (y *YaNFD) Start() {
	core.LogInfo(y, "Starting YaNFD")

	// Start profiler
	y.profiler.Start()

	// Initialize FIB table
	table.CreateFIBTable(core.GetConfig().Tables.Fib.Algorithm)

	// Create null face
	face.MakeNullLinkService(face.MakeNullTransport()).Run(nil)

	// Start management thread
	go mgmt.MakeMgmtThread().Run()

	// Create forwarding threads
	if fw.NumFwThreads < 1 || fw.NumFwThreads > fw.MaxFwThreads {
		core.LogFatal(y, "Number of forwarding threads must be in range [1, ", fw.MaxFwThreads, "]")
		os.Exit(2)
	}
	fw.Threads = make([]*fw.Thread, fw.NumFwThreads)
	var fwForDispatch []dispatch.FWThread
	for i := 0; i < fw.NumFwThreads; i++ {
		newThread := fw.NewThread(i)
		fw.Threads[i] = newThread
		fwForDispatch = append(fwForDispatch, newThread)
		go fw.Threads[i].Run()
	}
	dispatch.InitializeFWThreads(fwForDispatch)

	// Set up listeners for faces
	listenerCount := 0

	// Create unicast UDP face
	if core.GetConfig().Faces.Udp.EnabledUnicast {
		udpAddrs := []*net.UDPAddr{{
			IP:   net.IPv4zero,
			Port: int(face.UDPUnicastPort),
		}, {
			IP:   net.IPv6zero,
			Port: int(face.UDPUnicastPort),
		}}

		for _, udpAddr := range udpAddrs {
			uri := fmt.Sprintf("udp://%s", udpAddr)
			udpListener, err := face.MakeUDPListener(defn.DecodeURIString(uri))
			if err != nil {
				core.LogError(y, "Unable to create UDP listener for ", uri, ": ", err)
			} else {
				listenerCount++
				go udpListener.Run()
				y.udpListeners = append(y.udpListeners, udpListener)
				core.LogInfo(y, "Created unicast UDP listener for ", uri)
			}
		}
	}

	// Create unicast TCP face
	if core.GetConfig().Faces.Tcp.Enabled {
		tcpAddrs := []*net.TCPAddr{{
			IP:   net.IPv4zero,
			Port: int(face.TCPUnicastPort),
		}, {
			IP:   net.IPv6zero,
			Port: int(face.TCPUnicastPort),
		}}

		for _, tcpAddr := range tcpAddrs {
			uri := fmt.Sprintf("tcp://%s", tcpAddr)
			tcpListener, err := face.MakeTCPListener(defn.DecodeURIString(uri))
			if err != nil {
				core.LogError(y, "Unable to create TCP listener for ", uri, ": ", err)
			} else {
				listenerCount++
				go tcpListener.Run()
				y.tcpListeners = append(y.tcpListeners, tcpListener)
				core.LogInfo(y, "Created unicast TCP listener for ", uri)
			}
		}
	}

	// Create multicast UDP face on each non-loopback interface
	if core.GetConfig().Faces.Udp.EnabledMulticast {
		ifaces, err := net.Interfaces()
		if err != nil {
			core.LogError(y, "Unable to access network interfaces: ", err)
		}

		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				core.LogInfo(y, "Skipping interface ", iface.Name, " because not up")
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				core.LogError(y, "Unable to access addresses on network interface ", iface.Name, ": ", err)
				continue
			}

			for _, addr := range addrs {
				ipAddr := addr.(*net.IPNet)
				udpAddr := net.UDPAddr{
					IP:   ipAddr.IP,
					Zone: iface.Name,
					Port: int(face.UDPMulticastPort),
				}
				uri := fmt.Sprintf("udp://%s", &udpAddr)

				if !addr.(*net.IPNet).IP.IsLoopback() {
					multicastUDPTransport, err := face.MakeMulticastUDPTransport(defn.DecodeURIString(uri))
					if err != nil {
						core.LogError(y, "Unable to create MulticastUDPTransport for ", uri, ": ", err)
						continue
					}

					face.MakeNDNLPLinkService(
						multicastUDPTransport,
						face.MakeNDNLPLinkServiceOptions(),
					).Run(nil)

					listenerCount++
					core.LogInfo(y, "Created multicast UDP face for ", uri)
				}
			}
		}
	}

	// Set up Unix stream listener
	if core.GetConfig().Faces.Unix.Enabled {
		unixListener, err := face.MakeUnixStreamListener(defn.MakeUnixFaceURI(face.UnixSocketPath))
		if err != nil {
			core.LogError(y, "Unable to create Unix stream listener at ", face.UnixSocketPath, ": ", err)
		} else {
			listenerCount++
			go unixListener.Run()
			y.unixListener = unixListener
			core.LogInfo(y, "Created Unix stream listener for ", face.UnixSocketPath)
		}
	}

	// Set up WebSocket listener
	if core.GetConfig().Faces.WebSocket.Enabled {
		cfg := face.WebSocketListenerConfig{
			Bind:       core.GetConfig().Faces.WebSocket.Bind,
			Port:       core.GetConfig().Faces.WebSocket.Port,
			TLSEnabled: core.GetConfig().Faces.WebSocket.TlsEnabled,
			TLSCert:    core.ResolveConfigFileRelPath(core.GetConfig().Faces.WebSocket.TlsCert),
			TLSKey:     core.ResolveConfigFileRelPath(core.GetConfig().Faces.WebSocket.TlsKey),
		}

		wsListener, err := face.NewWebSocketListener(cfg)
		if err != nil {
			core.LogError(y, "Unable to create ", cfg, ": ", err)
		} else {
			listenerCount++
			go wsListener.Run()
			y.wsListener = wsListener
			core.LogInfo(y, "Created ", cfg)
		}
	}

	// Check if any faces were created
	if listenerCount <= 0 {
		core.LogFatal(y, "No face or listener is successfully created. Quit.")
		os.Exit(2)
	}
}

// Stop shuts down YaNFD.
func (y *YaNFD) Stop() {
	core.LogInfo(y, "Forwarder shutting down ...")
	core.ShouldQuit = true

	// Stop profiler
	y.profiler.Stop()

	// Wait for unix socket listener to quit
	if y.unixListener != nil {
		y.unixListener.Close()
	}
	if y.wsListener != nil {
		y.wsListener.Close()
	}

	// Wait for UDP listener to quit
	for _, udpListener := range y.udpListeners {
		udpListener.Close()
	}

	// Wait for TCP listeners to quit
	for _, tcpListener := range y.tcpListeners {
		tcpListener.Close()
	}

	// Tell all faces to quit
	for _, face := range face.FaceTable.GetAll() {
		face.Close()
	}

	// Tell all forwarding threads to quit
	for _, fw := range fw.Threads {
		fw.TellToQuit()
	}

	// Wait for all forwarding threads to have quit
	for _, fw := range fw.Threads {
		<-fw.HasQuit
	}
}
