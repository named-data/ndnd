//go:build !tinygo

package face

import (
	"fmt"
	"net/netip"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/quic-go/webtransport-go"
)

type HTTP3Transport struct {
	transportBase
	c *webtransport.Session
}

// (AI GENERATED DESCRIPTION): Creates a new HTTP3Transport instance, initializing it with the given remote and local addresses, configuring its transport base parameters, and marking it as running.
func NewHTTP3Transport(remote, local netip.AddrPort, c *webtransport.Session) (t *HTTP3Transport) {
	t = &HTTP3Transport{c: c}
	t.makeTransportBase(defn.MakeQuicFaceURI(remote), defn.MakeQuicFaceURI(local), spec_mgmt.PersistencyOnDemand, defn.NonLocal, defn.PointToPoint, 1000)
	t.running.Store(true)
	return
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable string summarizing the HTTP/3 transport, including its face ID, remote URI, and local URI.
func (t *HTTP3Transport) String() string {
	return fmt.Sprintf("http3-transport (faceid=%d remote=%s local=%s)", t.faceID, t.remoteURI, t.localURI)
}

// (AI GENERATED DESCRIPTION): Returns true if the given persistency setting is `OnDemand`, indicating the transport should use persistent mode only in that case.
func (t *HTTP3Transport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	return persistency == spec_mgmt.PersistencyOnDemand
}

// (AI GENERATED DESCRIPTION): Returns the current size, in bytes, of the outgoing send queue for this HTTP/3 transport.
func (t *HTTP3Transport) GetSendQueueSize() uint64 {
	return 0
}

// (AI GENERATED DESCRIPTION): Sends a given frame over the HTTP/3 transport if it is running and the frame size is within the MTU, logs and handles any send errors (closing the transport on failure), and updates the outbound byte counter.
func (t *HTTP3Transport) sendFrame(frame []byte) {
	if !t.running.Load() {
		return
	}

	if len(frame) > t.MTU() {
		core.Log.Warn(t, "Attempted to send frame larger than MTU")
		return
	}

	e := t.c.SendDatagram(frame)
	if e != nil {
		core.Log.Warn(t, "Unable to send on socket - Face DOWN", "err", e)
		t.Close()
		return
	}

	t.nOutBytes += uint64(len(frame))
}

// (AI GENERATED DESCRIPTION): Continuously reads datagrams from the WebTransport connection, discarding packets larger than MaxNDNPacketSize, logging read errors, updating the input byte counter, and forwarding valid frames to the link service until a read error causes the transport to close.
func (t *HTTP3Transport) runReceive() {
	defer t.Close()

	for {
		message, err := t.c.ReceiveDatagram(t.c.Context())
		if err != nil {
			core.Log.Warn(t, "Unable to read from WebTransport - DROP and Face DOWN", "err", err)
			return
		}

		if len(message) > defn.MaxNDNPacketSize {
			core.Log.Warn(t, "Received too much data without valid TLV block")
			continue
		}

		t.nInBytes += uint64(len(message))
		t.linkService.handleIncomingFrame(message)
	}
}

// (AI GENERATED DESCRIPTION): Closes the HTTP/3 transport by marking it stopped and shutting down the underlying connection without error.
func (t *HTTP3Transport) Close() {
	t.running.Store(false)
	t.c.CloseWithError(0, "")
}
