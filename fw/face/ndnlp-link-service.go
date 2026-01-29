/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2022 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"math"
	"runtime"
	"time"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

const lpPacketOverhead = 1 + 3 + 1 + 3 // LpPacket+Fragment
const pitTokenOverhead = 1 + 1 + 6
const congestionMarkOverhead = 3 + 1 + 8

const (
	FaceFlagLocalFields = 1 << iota
	FaceFlagLpReliabilityEnabled
	FaceFlagCongestionMarking
)

// NDNLPLinkServiceOptions contains the settings for an NDNLPLinkService.
type NDNLPLinkServiceOptions struct {
	IsFragmentationEnabled bool
	IsReassemblyEnabled    bool

	IsConsumerControlledForwardingEnabled bool

	IsIncomingFaceIndicationEnabled bool

	IsLocalCachePolicyEnabled bool

	IsCongestionMarkingEnabled bool

	BaseCongestionMarkingInterval   time.Duration
	DefaultCongestionThresholdBytes uint64
}

// (AI GENERATED DESCRIPTION): Creates and returns the default NDN link‑service options: a 100 ms congestion‑marking interval, a 64 KiB congestion threshold, and both reassembly and fragmentation enabled.
func MakeNDNLPLinkServiceOptions() NDNLPLinkServiceOptions {
	return NDNLPLinkServiceOptions{
		BaseCongestionMarkingInterval:   time.Duration(100) * time.Millisecond,
		DefaultCongestionThresholdBytes: uint64(math.Pow(2, 16)),
		IsReassemblyEnabled:             true,
		IsFragmentationEnabled:          true,
	}
}

// NDNLPLinkService is a link service implementing the NDNLPv2 link protocol
type NDNLPLinkService struct {
	linkServiceBase
	options        NDNLPLinkServiceOptions
	headerOverhead int

	// Fragment reassembly ring buffer
	reassemblyIndex   int
	reassemblyBuffers [16]struct {
		sequence uint64
		buffer   enc.Wire
	}

	// Outgoing packet state
	nextSequence             uint64
	nextTxSequence           uint64
	lastTimeCongestionMarked time.Time
	congestionCheck          uint64
	outFrame                 []byte
}

// MakeNDNLPLinkService creates a new NDNLPv2 link service
func MakeNDNLPLinkService(transport transport, options NDNLPLinkServiceOptions) *NDNLPLinkService {
	l := new(NDNLPLinkService)
	l.makeLinkServiceBase()
	l.transport = transport
	l.transport.setLinkService(l)
	l.options = options
	l.computeHeaderOverhead()

	// Initialize outgoing packet state
	l.nextSequence = 0
	l.nextTxSequence = 0
	l.congestionCheck = 0
	l.outFrame = make([]byte, defn.MaxNDNPacketSize)

	return l
}

// Options gets the settings of the NDNLPLinkService.
func (l *NDNLPLinkService) Options() NDNLPLinkServiceOptions {
	return l.options
}

// SetOptions changes the settings of the NDNLPLinkService.
func (l *NDNLPLinkService) SetOptions(options NDNLPLinkServiceOptions) {
	l.options = options
	l.computeHeaderOverhead()
}

// (AI GENERATED DESCRIPTION): Computes and stores the total byte size of the LP packet header, adding optional fragmentation and incoming face‑ID fields when those features are enabled.
func (l *NDNLPLinkService) computeHeaderOverhead() {
	l.headerOverhead = lpPacketOverhead // LpPacket (Type + Length of up to 2^16)

	if l.options.IsFragmentationEnabled {
		l.headerOverhead += 1 + 1 + 8 // Sequence
		l.headerOverhead += 1 + 1 + 2 // FragIndex (max 2^16 fragments)
		l.headerOverhead += 1 + 1 + 2 // FragCount
	}

	if l.options.IsIncomingFaceIndicationEnabled {
		l.headerOverhead += 3 + 1 + 8 // IncomingFaceId
	}
}

// Run starts the face and associated goroutines
func (l *NDNLPLinkService) Run(initial []byte) {
	if l.transport == nil {
		core.Log.Error(l, "Unable to start face due to unset transport")
		return
	}

	// Add self to face table. Removed in runSend.
	FaceTable.Add(l)

	// Process initial incoming frame
	if initial != nil {
		l.handleIncomingFrame(initial)
	}

	// Start transport goroutines
	go l.runReceive()
	go l.runSend()
}

// (AI GENERATED DESCRIPTION): Runs the link service’s receive loop (optionally locking it to a single OS thread) and signals that the receive goroutine has stopped by sending a value on the `stopped` channel.
func (l *NDNLPLinkService) runReceive() {
	if CfgLockThreadsToCores() {
		runtime.LockOSThread()
	}

	l.transport.runReceive()
	l.stopped <- true
}

// (AI GENERATED DESCRIPTION): Runs the link service’s send loop: it locks the OS thread if configured, repeatedly takes packets from the send queue to transmit them, and removes the face from the FaceTable when the service stops.
func (l *NDNLPLinkService) runSend() {
	if CfgLockThreadsToCores() {
		runtime.LockOSThread()
	}

	for {
		select {
		case pkt := <-l.sendQueue:
			sendPacket(l, pkt)
		case <-l.stopped:
			FaceTable.Remove(l.transport.FaceID())
			return
		}
	}
}

// (AI GENERATED DESCRIPTION): Sends a link‑layer packet by applying congestion marks, PIT tokens, and optional fragmentation, then encodes the resulting LP frames and transmits them over the transport while updating packet counters.
func sendPacket(l *NDNLPLinkService, out dispatch.OutPkt) {
	pkt := out.Pkt
	wire := pkt.Raw

	// Counters
	if pkt.L3.Interest != nil {
		l.nOutInterests++
	} else if pkt.L3.Data != nil {
		l.nOutData++
	}

	// Congestion marking
	congestionMark := pkt.CongestionMark // from upstream
	if l.checkCongestion(wire) && !congestionMark.IsSet() {
		core.Log.Debug(l, "Marking congestion")
		congestionMark = optional.Some(uint64(1)) // ours
	}

	// Calculate effective MTU after accounting for packet-specific overhead
	effectiveMtu := l.transport.MTU() - l.headerOverhead
	if pl := len(out.PitToken); pl > 0 {
		if pl != 6 {
			panic("[BUG] Outgoing PIT token length must be 6 bytes")
		}
		effectiveMtu -= pitTokenOverhead
	}
	if congestionMark.IsSet() {
		effectiveMtu -= congestionMarkOverhead
	}

	// Fragment packet if necessary
	var fragments []*defn.FwLpPacket
	frameLen := int(wire.Length())
	if frameLen > effectiveMtu {
		if !l.options.IsFragmentationEnabled {
			core.Log.Info(l, "Attempted to send frame over MTU on link without fragmentation - DROP")
			return
		}

		// Split up fragment
		fragCount := (frameLen + effectiveMtu - 1) / effectiveMtu
		fragments = make([]*defn.FwLpPacket, fragCount)

		reader := enc.NewWireView(wire)
		for i := range fragments {
			// Read till effective mtu or end of wire
			readSize := effectiveMtu
			if i == fragCount-1 {
				readSize = frameLen - effectiveMtu*(fragCount-1)
			}

			frag, err := reader.ReadWire(readSize)
			if err != nil {
				core.Log.Fatal(l, "Unexpected wire reading error")
			}

			// Create fragment with sequence and index
			l.nextSequence++
			fragments[i] = &defn.FwLpPacket{
				Fragment:  frag,
				Sequence:  optional.Some(l.nextSequence),
				FragIndex: optional.Some(uint64(i)),
				FragCount: optional.Some(uint64(fragCount)),
			}
		}
	} else {
		// No fragmentation necessary
		fragments = []*defn.FwLpPacket{{Fragment: wire}}
	}

	// Send fragment(s)
	for _, fragment := range fragments {
		// PIT tokens
		if len(out.PitToken) > 0 {
			fragment.PitToken = out.PitToken
		}

		// Incoming face indication
		if l.options.IsIncomingFaceIndicationEnabled {
			fragment.IncomingFaceId = optional.Some(out.InFace)
		}

		// Congestion marking
		if congestionMark.IsSet() {
			fragment.CongestionMark = congestionMark
		}

		// Encode final LP frame
		pkt := defn.FwPacket{LpPacket: fragment}
		frameWire := pkt.Encode()
		if frameWire == nil {
			core.Log.Error(l, "Unable to encode fragment - DROP")
			break
		}

		// Use preallocated buffer for outgoing frame
		l.outFrame = l.outFrame[:0]
		for _, b := range frameWire {
			l.outFrame = append(l.outFrame, b...)
		}
		l.transport.sendFrame(l.outFrame)
	}
}

// (AI GENERATED DESCRIPTION): Processes an incoming link‑layer frame: it decodes the L2 packet, optionally reassembles fragmented frames, extracts the encapsulated L3 Interest or Data, updates counters, and dispatches the packet to the appropriate handler.
func (l *NDNLPLinkService) handleIncomingFrame(frame []byte) {
	// We have to copy so receive transport buffer can be reused
	frameCopy := make([]byte, len(frame))
	copy(frameCopy, frame)

	// All incoming frames come through a link service
	// Attempt to decode buffer into LpPacket
	pkt := &defn.Pkt{
		IncomingFaceID: l.faceID,
	}

	wire := enc.Wire{frameCopy}
	L2, err := defn.ParseFwPacket(enc.NewWireView(wire), false)
	if err != nil {
		core.Log.Error(l, "Unable to decode incoming frame", "err", err)
		return
	}

	if L2.LpPacket == nil {
		// Bare Data or Interest packet
		pkt.Raw = wire
		pkt.L3 = L2
	} else {
		// NDNLPv2 frame
		LP := L2.LpPacket
		fragment := LP.Fragment

		// If there is no fragment, then IDLE packet, drop.
		if len(fragment) == 0 {
			core.Log.Trace(l, "IDLE frame - DROP")
			return
		}

		// Reassembly
		if l.options.IsReassemblyEnabled && LP.Sequence.IsSet() {
			fragIndex := uint64(0)
			if v, ok := LP.FragIndex.Get(); ok {
				fragIndex = v
			}
			fragCount := uint64(1)
			if v, ok := LP.FragCount.Get(); ok {
				fragCount = v
			}
			baseSequence := LP.Sequence.Unwrap() - fragIndex

			core.Log.Trace(l, "Received fragment", "index", fragIndex, "count", fragCount, "base", baseSequence)
			if fragIndex == 0 && fragCount == 1 {
				// Bypass reassembly since only one fragment
			} else {
				fragment = l.reassemble(LP, baseSequence, fragIndex, fragCount)
				if fragment == nil {
					// Nothing more to be done, so return
					return
				}
			}
		} else if LP.FragCount.IsSet() || LP.FragIndex.IsSet() {
			core.Log.Warn(l, "Received NDNLPv2 frame with fragmentation fields but reassembly disabled - DROP")
			return
		}

		// Congestion mark
		pkt.CongestionMark = LP.CongestionMark

		// Consumer-controlled forwarding (NextHopFaceId)
		if l.options.IsConsumerControlledForwardingEnabled {
			pkt.NextHopFaceID = LP.NextHopFaceId
		}

		// No need to copy the pit token since it's already in its own buffer
		// See the generated code for defn.FwLpPacket
		pkt.PitToken = LP.PitToken

		// Parse inner packet in place
		L3, err := defn.ParseFwPacket(enc.NewWireView(fragment), false)
		if err != nil {
			return
		}
		pkt.Raw = fragment
		pkt.L3 = L3
	}

	// Dispatch and update counters
	if pkt.L3.Interest != nil {
		l.nInInterests++
		l.dispatchInterest(pkt)
	} else if pkt.L3.Data != nil {
		l.nInData++
		l.dispatchData(pkt)
	} else {
		core.Log.Error(l, "Received packet of unknown type")
	}
}

// (AI GENERATED DESCRIPTION): Reassembles a fragmented FwLpPacket into a complete wire by storing each fragment in a sequence‑indexed buffer, validating fragment count and index, and returning the full packet once all fragments are received, then clearing the buffer.
func (l *NDNLPLinkService) reassemble(
	frame *defn.FwLpPacket,
	baseSequence uint64,
	fragIndex uint64,
	fragCount uint64,
) enc.Wire {
	var buffer enc.Wire = nil
	var bufIndex int = 0

	// Check if reassembly buffer already exists
	for i := range l.reassemblyBuffers {
		if l.reassemblyBuffers[i].sequence == baseSequence {
			bufIndex = i
			buffer = l.reassemblyBuffers[bufIndex].buffer
			break
		}
	}

	// Use the next available buffer if this is a new sequence
	if buffer == nil {
		bufIndex = (l.reassemblyIndex + 1) % len(l.reassemblyBuffers)
		l.reassemblyIndex = bufIndex
		l.reassemblyBuffers[bufIndex].sequence = baseSequence
		l.reassemblyBuffers[bufIndex].buffer = make(enc.Wire, fragCount)
		buffer = l.reassemblyBuffers[bufIndex].buffer
	}

	// Validate fragCount has not changed
	if fragCount != uint64(len(buffer)) {
		core.Log.Warn(l, "Received fragment count does not match expected count",
			"count", fragCount, "expected", len(buffer), "base", baseSequence)
		return nil
	}

	// Validate fragIndex is valid
	if fragIndex >= uint64(len(buffer)) {
		core.Log.Warn(l, "Received fragment index out of range",
			"index", fragIndex, "count", fragCount, "base", baseSequence)
		return nil
	}

	// Store fragment in buffer
	buffer[fragIndex] = frame.Fragment.Join() // should be only one fragment

	// Check if all fragments have been received
	for _, frag := range buffer {
		if len(frag) == 0 {
			return nil // not all fragments received
		}
	}

	// All fragments received, free up buffer
	l.reassemblyBuffers[bufIndex].sequence = 0
	l.reassemblyBuffers[bufIndex].buffer = nil

	return buffer
}

// (AI GENERATED DESCRIPTION): Returns true if the packet should be marked for congestion, based on accumulated packet size, send‑queue depth, and time since the last congestion mark.
func (l *NDNLPLinkService) checkCongestion(wire enc.Wire) bool {
	if !CfgCongestionMarking() {
		return false
	}

	// GetSendQueueSize is expensive, so only check every 1/2 of the threshold
	// and only if we can mark congestion for this particular packet
	if l.congestionCheck > l.options.DefaultCongestionThresholdBytes {
		now := time.Now()
		if now.After(l.lastTimeCongestionMarked.Add(l.options.BaseCongestionMarkingInterval)) &&
			l.transport.GetSendQueueSize() > l.options.DefaultCongestionThresholdBytes {
			l.lastTimeCongestionMarked = now
			return true
		}

		l.congestionCheck = 0 // reset
	}

	l.congestionCheck += wire.Length() // approx
	return false
}

// (AI GENERATED DESCRIPTION): Computes and returns a bitmask of Face flags for the link service, setting bits for local fields when consumer‑controlled forwarding is enabled and for congestion marking when enabled.
func (op *NDNLPLinkServiceOptions) Flags() (ret uint64) {
	if op.IsConsumerControlledForwardingEnabled {
		ret |= FaceFlagLocalFields
	}
	if op.IsCongestionMarkingEnabled {
		ret |= FaceFlagCongestionMarking
	}
	return
}
