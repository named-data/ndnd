/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"strconv"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

// InternalTransport is a transport for use by internal YaNFD modules (e.g., management).
type InternalTransport struct {
	recvQueue chan []byte // Contains pending packets sent to internal component
	sendQueue chan []byte // Contains pending packets sent by the internal component
	transportBase
}

// MakeInternalTransport makes an InternalTransport.
func MakeInternalTransport() *InternalTransport {
	t := new(InternalTransport)
	t.makeTransportBase(
		defn.MakeInternalFaceURI(),
		defn.MakeInternalFaceURI(),
		spec_mgmt.PersistencyPersistent,
		defn.Local,
		defn.PointToPoint,
		defn.MaxNDNPacketSize)
	t.recvQueue = make(chan []byte, faceQueueSize)
	t.sendQueue = make(chan []byte, faceQueueSize)
	t.running.Store(true)
	return t
}

// RegisterInternalTransport creates, registers, and starts an InternalTransport.
func RegisterInternalTransport() (LinkService, *InternalTransport) {
	transport := MakeInternalTransport()

	options := MakeNDNLPLinkServiceOptions()
	options.IsIncomingFaceIndicationEnabled = true
	options.IsConsumerControlledForwardingEnabled = true
	link := MakeNDNLPLinkService(transport, options)
	link.Run(nil)

	return link, transport
}

func (t *InternalTransport) String() string {
	return "InternalTransport, FaceID=" + strconv.FormatUint(t.faceID, 10) +
		", RemoteURI=" + t.remoteURI.String() + ", LocalURI=" + t.localURI.String()
}

// SetPersistency changes the persistency of the face.
func (t *InternalTransport) SetPersistency(persistency spec_mgmt.Persistency) bool {
	if persistency == t.persistency {
		return true
	}

	if persistency == spec_mgmt.PersistencyPersistent {
		t.persistency = persistency
		return true
	}

	return false
}

// GetSendQueueSize returns the current size of the send queue.
func (t *InternalTransport) GetSendQueueSize() uint64 {
	return 0
}

// Send sends a packet from the perspective of the internal component.
func (t *InternalTransport) Send(lpPkt *spec.LpPacket) {
	pkt := &spec.Packet{LpPacket: lpPkt}
	encoder := spec.PacketEncoder{}
	encoder.Init(pkt)
	lpPacketWire := encoder.Encode(pkt)
	if lpPacketWire == nil {
		core.LogWarn(t, "Unable to encode block to send - DROP")
		return
	}
	t.sendQueue <- lpPacketWire.Join()
}

// Receive receives a packet from the perspective of the internal component.
func (t *InternalTransport) Receive() *spec.LpPacket {
	for frame := range t.recvQueue {
		packet, _, err := spec.ReadPacket(enc.NewBufferReader(frame))
		if err != nil {
			core.LogWarn(t, "Unable to decode received block - DROP: ", err)
			continue
		}

		lpPkt := packet.LpPacket
		if packet.LpPacket == nil || lpPkt.Fragment.Length() == 0 {
			core.LogWarn(t, "Received empty fragment - DROP")
			continue
		}

		return lpPkt
	}

	return nil
}

func (t *InternalTransport) sendFrame(frame []byte) {
	if len(frame) > t.MTU() {
		core.LogWarn(t, "Attempted to send frame larger than MTU - DROP")
		return
	}

	t.nOutBytes += uint64(len(frame))

	frameCopy := make([]byte, len(frame))
	copy(frameCopy, frame)
	t.recvQueue <- frameCopy
}

func (t *InternalTransport) runReceive() {
	for frame := range t.sendQueue {
		if len(frame) > defn.MaxNDNPacketSize {
			core.LogWarn(t, "Component trying to send too much data - DROP")
			continue
		}

		t.nInBytes += uint64(len(frame))
		t.linkService.handleIncomingFrame(frame)
	}
}

func (t *InternalTransport) Close() {
	if t.running.Swap(false) {
		// do not close the send queue, let it be garbage collected
		close(t.recvQueue)
	}
}
