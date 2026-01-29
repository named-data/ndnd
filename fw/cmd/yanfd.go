package cmd

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/face"
	"github.com/named-data/ndnd/fw/fw"
	"github.com/named-data/ndnd/fw/mgmt"
	"github.com/named-data/ndnd/fw/table"
	"github.com/named-data/ndnd/std/utils"
)

// YaNFD is the wrapper class for the NDN Forwarding Daemon.
// Note: only one instance of this class should be created.
type YaNFD struct {
	config   *core.Config
	profiler *Profiler

	unixListener *face.UnixStreamListener
	wsListener   *face.WebSocketListener
	h3Listener   *face.HTTP3Listener
	tcpListeners []*face.TCPListener
	udpListeners []*face.UDPListener
}

// NewYaNFD creates a YaNFD. Don't call this function twice.
func NewYaNFD(config *core.Config) *YaNFD {
	// Provide global configuration.
	core.C = config
	core.StartTimestamp = time.Now()

	// Initialize all modules here
	core.OpenLogger()
	face.Initialize()
	table.Initialize()

	return &YaNFD{
		config:   config,
		profiler: NewProfiler(config),
	}
}

// (AI GENERATED DESCRIPTION): Returns the identifier string “yanfd” for a YaNFD instance.
func (y *YaNFD) String() string {
	return "yanfd"
}

// Start runs YaNFD. Note: this function may exit the program when there is error.
// This function is non-blocking.
func (y *YaNFD) Start() {
	core.Log.Info(y, "Starting NDN forwarder", "version", utils.NDNdVersion)

	// Start profiler
	y.profiler.Start()

	// Create null face
	face.MakeNullLinkService(face.MakeNullTransport()).Run(nil)

	// Start management thread
	go mgmt.MakeMgmtThread().Run()

	// Create forwarding threads
	if fw.CfgNumThreads() < 1 || fw.CfgNumThreads() > fw.MaxFwThreads {
		core.Log.Fatal(y, "Number of forwarding threads out of range", "range", fmt.Sprintf("[1, %d]", fw.MaxFwThreads))
		os.Exit(2)
	}
	fw.Threads = make([]*fw.Thread, fw.CfgNumThreads())
	var fwForDispatch []dispatch.FWThread
	for i := range fw.CfgNumThreads() {
		newThread := fw.NewThread(i)
		fw.Threads[i] = newThread
		fwForDispatch = append(fwForDispatch, newThread)
		go fw.Threads[i].Run()
	}
	dispatch.InitializeFWThreads(fwForDispatch)

	// Set up listeners for faces
	listenerCount := 0

	// Create unicast TCP face
	if core.C.Faces.Tcp.Enabled {
		tcpAddrs := []*net.TCPAddr{{
			IP:   net.IPv4zero,
			Port: face.CfgTCPUnicastPort(),
		}, {
			IP:   net.IPv6zero,
			Port: face.CfgTCPUnicastPort(),
		}}

		for _, tcpAddr := range tcpAddrs {
			uri := fmt.Sprintf("tcp://%s", tcpAddr)
			tcpListener, err := face.MakeTCPListener(defn.DecodeURIString(uri))
			if err != nil {
				core.Log.Error(y, "Unable to create TCP listener", "uri", uri, "err", err)
			} else {
				listenerCount++
				go tcpListener.Run()
				y.tcpListeners = append(y.tcpListeners, tcpListener)
				core.Log.Info(y, "Created unicast TCP listener", "uri", uri)
			}
		}
	}

	// Utility to create unicast UDP face
	createUdpFace := func(ipAddr net.IP, zone string) {
		uri := fmt.Sprintf("udp://%s", &net.UDPAddr{
			IP:   ipAddr,
			Port: face.CfgUDPUnicastPort(),
			Zone: zone,
		})

		udpListener, err := face.MakeUDPListener(defn.DecodeURIString(uri))
		if err != nil {
			core.Log.Error(y, "Unable to create UDP listener", "uri", uri, "err", err)
		} else {
			listenerCount++
			go udpListener.Run()
			y.udpListeners = append(y.udpListeners, udpListener)
			core.Log.Info(y, "Created unicast UDP listener", "uri", uri)
		}
	}

	// On Linux and Windows, create a single UDP face for all interfaces.
	// On macOS, create a UDP face for each interface (see below)
	if runtime.GOOS != "darwin" {
		createUdpFace(net.IPv4zero, "")
		createUdpFace(net.IPv6zero, "")
	}

	// Create UDP faces on each non-loopback interface
	if core.C.Faces.Udp.EnabledUnicast || core.C.Faces.Udp.EnabledMulticast {
		ifaces, err := net.Interfaces()
		if err != nil {
			core.Log.Error(y, "Unable to access network interfaces", "err", err)
		}

		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				core.Log.Info(y, "Skipping interface because not up", "iface", iface.Name)
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				core.Log.Error(y, "Unable to access addresses on network interface", "iface", iface.Name, "err", err)
				continue
			}

			for _, addr := range addrs {
				ipAddr := addr.(*net.IPNet)

				// Create unicast UDP faces on each interface for macOS.
				// Do not make a single listener here for all interfaces.
				// https://github.com/named-data/ndnd/issues/144
				if runtime.GOOS == "darwin" && core.C.Faces.Udp.EnabledUnicast {
					createUdpFace(ipAddr.IP, iface.Name)
				}

				// Create multicast UDP faces
				if core.C.Faces.Udp.EnabledMulticast {
					uri := fmt.Sprintf("udp://%s", &net.UDPAddr{
						IP:   ipAddr.IP,
						Port: face.CfgUDPMulticastPort(),
						Zone: iface.Name,
					})

					if !addr.(*net.IPNet).IP.IsLoopback() {
						multicastUDPTransport, err := face.MakeMulticastUDPTransport(defn.DecodeURIString(uri))
						if err != nil {
							core.Log.Error(y, "Unable to create MulticastUDPTransport", "uri", uri, "err", err)
							continue
						}
						face.MakeNDNLPLinkService(multicastUDPTransport, face.MakeNDNLPLinkServiceOptions()).Run(nil)

						listenerCount++
						core.Log.Info(y, "Created multicast UDP face", "uri", uri)
					}
				}
			}
		}
	}

	// Set up Unix stream listener
	if core.C.Faces.Unix.Enabled {
		uri := defn.MakeUnixFaceURI(face.CfgUnixSocketPath())
		unixListener, err := face.MakeUnixStreamListener(uri)
		if err != nil {
			core.Log.Error(y, "Unable to create Unix stream listener", "path", face.CfgUnixSocketPath(), "err", err)
		} else {
			listenerCount++
			go unixListener.Run()
			y.unixListener = unixListener
			core.Log.Info(y, "Created unix stream listener", "uri", uri)
		}
	}

	// Set up WebSocket listener
	if core.C.Faces.WebSocket.Enabled {
		cfg := face.WebSocketListenerConfig{
			Bind:       core.C.Faces.WebSocket.Bind,
			Port:       core.C.Faces.WebSocket.Port,
			TLSEnabled: core.C.Faces.WebSocket.TlsEnabled,
			TLSCert:    core.C.ResolveRelPath(core.C.Faces.WebSocket.TlsCert),
			TLSKey:     core.C.ResolveRelPath(core.C.Faces.WebSocket.TlsKey),
		}

		wsListener, err := face.NewWebSocketListener(cfg)
		if err != nil {
			core.Log.Error(y, "Unable to create WebSocket Listener", "cfg", cfg, "err", err)
		} else {
			listenerCount++
			go wsListener.Run()
			y.wsListener = wsListener
			core.Log.Info(y, "Created WebSocket listener", "uri", cfg.URL().String())
		}
	}

	// Set up HTTP/3 WebTransport listener
	if c := core.C.Faces.HTTP3; c.Enabled {
		cfg := face.HTTP3ListenerConfig{
			Bind:    c.Bind,
			Port:    c.Port,
			TLSCert: c.TlsCert,
			TLSKey:  c.TlsKey,
		}

		h3Listener, err := face.NewHTTP3Listener(cfg)
		if err != nil {
			core.Log.Error(y, "Unable to create HTTP/3 WebTransport Listener", "cfg", cfg, "err", err)
		} else {
			listenerCount++
			go h3Listener.Run()
			y.h3Listener = h3Listener
			core.Log.Info(y, "Created HTTP/3 WebTransport listener", "uri", cfg.URL().String())
		}
	}

	// Check if any faces were created
	if listenerCount <= 0 {
		core.Log.Fatal(y, "No face or listener is successfully created. Quit.")
		os.Exit(2)
	}
}

// Stop shuts down YaNFD.
func (y *YaNFD) Stop() {
	// Close log file last
	defer core.CloseLogger()

	// Stop the forwarder
	core.Log.Info(y, "Stopping NDN forwarder")
	defer core.Log.Info(y, "Stopped NDN forwarder")

	// Break all loops
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
