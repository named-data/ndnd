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
	"strconv"
	"time"

	"github.com/named-data/ndnd/fw/core"
	defn "github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/utils"
)

const lpPacketOverhead = 1 + 3
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

	// Receive
	partialMessageStore map[uint64][][]byte

	// Send
	nextSequence             uint64
	nextTxSequence           uint64
	lastTimeCongestionMarked time.Time
	BufferReader             enc.BufferReader
	congestionCheck          uint64
	outFrame                 []byte
	outWire                  enc.Wire
}

// MakeNDNLPLinkService creates a new NDNLPv2 link service
func MakeNDNLPLinkService(transport transport, options NDNLPLinkServiceOptions) *NDNLPLinkService {
	l := new(NDNLPLinkService)
	l.makeLinkServiceBase()
	l.transport = transport
	l.transport.setLinkService(l)
	l.options = options
	l.computeHeaderOverhead()

	l.partialMessageStore = make(map[uint64][][]byte)
	l.nextSequence = 0
	l.nextTxSequence = 0
	l.congestionCheck = 0
	l.outFrame = make([]byte, defn.MaxNDNPacketSize*2)
	l.outWire = make(enc.Wire, defn.MaxNDNPacketSize)
	return l
}

func (l *NDNLPLinkService) String() string {
	if l.transport != nil {
		return "NDNLPLinkService, " + l.transport.String()
	}

	return "NDNLPLinkService, FaceID=" + strconv.FormatUint(l.faceID, 10)
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

func (l *NDNLPLinkService) computeHeaderOverhead() {
	l.headerOverhead = lpPacketOverhead // LpPacket (Type + Length of up to 2^16)

	if l.options.IsFragmentationEnabled {
		l.headerOverhead += 1 + 1 + 8 // Sequence
	}

	if l.options.IsFragmentationEnabled {
		l.headerOverhead += 1 + 1 + 2 + 1 + 1 + 2 // FragIndex/FragCount (Type + Length + up to 2^16 fragments)
	}

	if l.options.IsIncomingFaceIndicationEnabled {
		l.headerOverhead += 3 + 1 + 8 // IncomingFaceId
	}
}

// Run starts the face and associated goroutines
func (l *NDNLPLinkService) Run(initial []byte) {
	if l.transport == nil {
		core.LogError(l, "Unable to start face due to unset transport")
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

func (l *NDNLPLinkService) runReceive() {
	if lockThreadsToCores {
		runtime.LockOSThread()
	}

	l.transport.runReceive()
	l.stopped <- true
}

func (l *NDNLPLinkService) runSend() {
	if lockThreadsToCores {
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

func sendPacket(l *NDNLPLinkService, out dispatch.OutPkt) {
	pkt := out.Pkt
	wire := pkt.Raw

	// Counters
	if pkt.L3.Interest != nil {
		l.nOutInterests++
	} else if pkt.L3.Data != nil {
		l.nOutData++
	}

	now := time.Now()

	effectiveMtu := l.transport.MTU() - l.headerOverhead
	if pkt.PitToken != nil {
		effectiveMtu -= pitTokenOverhead
	}
	if pkt.CongestionMark != nil {
		effectiveMtu -= congestionMarkOverhead
	}

	// Fragmentation
	var fragments []*spec.LpPacket
	if len(wire) > effectiveMtu {
		if !l.options.IsFragmentationEnabled {
			core.LogInfo(l, "Attempted to send frame over MTU on link without fragmentation - DROP")
			return
		}

		// Split up fragment
		nFragments := int((len(wire) + effectiveMtu - 1) / effectiveMtu)
		fragments = make([]*spec.LpPacket, nFragments)
		reader := enc.NewBufferReader(wire)
		for i := 0; i < nFragments; i++ {
			readSize := effectiveMtu
			if i == nFragments-1 {
				readSize = len(wire) - effectiveMtu*(nFragments-1)
			}

			frag, err := reader.ReadWire(readSize)
			if err != nil {
				core.LogFatal(l, "Unexpected Wire reading error")
			}
			fragments[i] = &spec.LpPacket{Fragment: frag}
		}
		reader.Free()
	} else {
		fragments = []*spec.LpPacket{{Fragment: enc.Wire{wire}}}
	}

	// Sequence
	if len(fragments) > 1 {
		for _, fragment := range fragments {
			fragment.Sequence = utils.IdPtr(l.nextSequence)
			l.nextSequence++
		}
	}

	// Congestion marking
	congestionMark := pkt.CongestionMark // from upstream
	if congestionMarking {
		// GetSendQueueSize is expensive, so only check every 1/2 of the threshold
		// and only if we can mark congestion for this particular packet
		if l.congestionCheck > l.options.DefaultCongestionThresholdBytes {
			if now.After(l.lastTimeCongestionMarked.Add(l.options.BaseCongestionMarkingInterval)) &&
				l.transport.GetSendQueueSize() > l.options.DefaultCongestionThresholdBytes {
				core.LogWarn(l, "Marking congestion")
				congestionMark = utils.IdPtr[uint64](1) // ours
				l.lastTimeCongestionMarked = now
			}

			l.congestionCheck = 0
		}

		l.congestionCheck += uint64(len(wire)) // approx
	}

	// Send fragment(s)
	for _, fragment := range fragments {
		// PIT tokens
		if len(out.PitToken) > 0 {
			fragment.PitToken = out.PitToken
		}

		// Incoming face indication
		if l.options.IsIncomingFaceIndicationEnabled && out.InFace != nil {
			fragment.IncomingFaceId = out.InFace
		}

		// Congestion marking
		if congestionMark != nil {
			fragment.CongestionMark = congestionMark
		}

		pkt := spec.Packet{LpPacket: fragment}

		// Use preallocated buffers for outgoing frame
		encoder := spec.PacketEncoder{}
		wirePlan := encoder.Init(&pkt)
		outFrame := l.outFrame
		outWire := l.outWire[:len(wirePlan)]

		for i, l := range wirePlan {
			outWire[i] = outFrame[:l]
			outFrame = outFrame[l:]
		}
		encoder.EncodeInto(&pkt, outWire)

		// Consolidate fragments. Since we only overwrite behind, there is no conflict.
		nbytes := 0
		for _, b := range outWire {
			nbytes += copy(l.outFrame[nbytes:], b)
		}
		l.transport.sendFrame(l.outFrame[:nbytes])
	}
}

func (l *NDNLPLinkService) handleIncomingFrame(frame []byte) {
	// We have to copy so receive transport buffer can be reused
	wire := make([]byte, len(frame))
	copy(wire, frame)

	// All incoming frames come through a link service
	// Attempt to decode buffer into LpPacket
	pkt := &defn.Pkt{
		IncomingFaceID: utils.IdPtr(l.faceID),
	}

	L2r := enc.NewBufferReader(wire)
	L2, err := ReadPacketUnverified(L2r)
	L2r.Free()
	if err != nil {
		core.LogError(l, err)
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
			core.LogTrace(l, "IDLE frame - DROP")
			return
		}

		// Reassembly
		if l.options.IsReassemblyEnabled && LP.Sequence != nil {
			fragIndex := uint64(0)
			if LP.FragIndex != nil {
				fragIndex = *LP.FragIndex
			}
			fragCount := uint64(1)
			if LP.FragCount != nil {
				fragCount = *LP.FragCount
			}
			baseSequence := *LP.Sequence - fragIndex

			core.LogTrace(l, "Received fragment ", fragIndex, " of ", fragCount, " for ", baseSequence)
			if fragIndex == 0 && fragCount == 1 {
				// Bypass reassembly since only one fragment
			} else {
				fragment = l.reassemblePacket(LP, baseSequence, fragIndex, fragCount)
				if fragment == nil {
					// Nothing more to be done, so return
					return
				}
			}
		} else if LP.FragCount != nil || LP.FragIndex != nil {
			core.LogWarn(l, "Received NDNLPv2 frame containing fragmentation fields but reassembly disabled - DROP")
			return
		}

		// Congestion mark
		pkt.CongestionMark = LP.CongestionMark

		// Consumer-controlled forwarding (NextHopFaceId)
		if l.options.IsConsumerControlledForwardingEnabled && LP.NextHopFaceId != nil {
			pkt.NextHopFaceID = LP.NextHopFaceId
		}

		// Local cache policy
		if l.options.IsLocalCachePolicyEnabled && LP.CachePolicy != nil {
			pkt.CachePolicy = utils.IdPtr(LP.CachePolicy.CachePolicyType)
		}

		// PIT Token
		if len(LP.PitToken) > 0 {
			pkt.PitToken = make([]byte, len(LP.PitToken))
			copy(pkt.PitToken, LP.PitToken)
		}

		// Copy fragment to wire buffer
		wire = wire[:0]
		for _, b := range fragment {
			wire = append(wire, b...)
		}

		// Parse inner packet in place
		L3r := enc.NewBufferReader(wire)
		L3, err := ReadPacketUnverified(L3r)
		L3r.Free()
		if err != nil {
			return
		}
		pkt.Raw = wire
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
		core.LogError(l, "Attempted dispatch packet of unknown type")
	}
}

func (l *NDNLPLinkService) reassemblePacket(
	frame *spec.LpPacket,
	baseSequence uint64,
	fragIndex uint64,
	fragCount uint64,
) enc.Wire {
	_, hasSequence := l.partialMessageStore[baseSequence]
	if !hasSequence {
		// Create map entry
		l.partialMessageStore[baseSequence] = make([][]byte, fragCount)
	}

	// Insert into PartialMessageStore
	// Safe to call Join since there is only one fragment
	if len(frame.Fragment) > 1 {
		core.LogError("LpPacket should only have one fragment.")
	}
	l.partialMessageStore[baseSequence][fragIndex] = frame.Fragment.Join()

	// Determine whether it is time to reassemble
	receivedCount := 0
	receivedTotalLen := 0
	for _, fragment := range l.partialMessageStore[baseSequence] {
		if len(fragment) != 0 {
			receivedCount++
			receivedTotalLen += len(fragment)
		}
	}

	if receivedCount == len(l.partialMessageStore[baseSequence]) {
		// Time to reassemble!
		reassembled := make(enc.Wire, len(l.partialMessageStore[baseSequence]))
		for i, fragment := range l.partialMessageStore[baseSequence] {
			reassembled[i] = fragment
		}

		delete(l.partialMessageStore, baseSequence)
		return reassembled
	}

	return nil
}

func (op *NDNLPLinkServiceOptions) Flags() (ret uint64) {
	if op.IsConsumerControlledForwardingEnabled {
		ret |= FaceFlagLocalFields
	}
	if op.IsCongestionMarkingEnabled {
		ret |= FaceFlagCongestionMarking
	}
	return
}

// Reads a packet without validating the internal fields
func ReadPacketUnverified(reader enc.ParseReader) (ret defn.PacketIntf, err error) {
	context := spec.PacketParsingContext{}
	context.Init()
	packet, err := context.Parse(reader, false)
	if err != nil {
		return
	}

	if packet.LpPacket != nil {
		ret.LpPacket = packet.LpPacket
	} else if packet.Interest != nil {
		ret.Interest = packet.Interest
	} else if packet.Data != nil {
		ret.Data = packet.Data
	}

	return ret, nil
}
