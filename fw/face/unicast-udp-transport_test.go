package face

import (
	"net"
	"testing"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/stretchr/testify/require"
)

// Sending to a UDP endpoint that is not listening must not close the face:
// the kernel reports the ICMP port unreachable as ECONNREFUSED on a later
// write, which is transient (e.g. the remote forwarder is restarting).
func TestUnicastUDPSendToClosedPortKeepsFace(t *testing.T) {
	prevPort := core.C.Faces.Udp.PortUnicast
	core.C.Faces.Udp.PortUnicast = 0 // ephemeral local port
	defer func() { core.C.Faces.Udp.PortUnicast = prevPort }()

	// Find a port that nobody is listening on
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()

	remote := defn.MakeUDPFaceURI(4, "127.0.0.1", uint16(port))
	tr, err := MakeUnicastUDPTransport(remote, nil, spec_mgmt.PersistencyPermanent)
	require.NoError(t, err)
	defer tr.Close()

	for range 5 {
		tr.sendFrame([]byte{0x05, 0x00})
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, tr.IsRunning(), "face closed after ECONNREFUSED")
}
