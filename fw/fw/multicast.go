/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import (
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
)

const MulticastSuppressionTime = 500 * time.Millisecond

// Multicast is a forwarding strategy that forwards Interests to all nexthop faces.
type Multicast struct {
	StrategyBase
}

func init() {
	strategyTypes = append(strategyTypes, func() Strategy {
		return &Multicast{}
	})
	StrategyVersions["multicast"] = []uint64{1}
}

func (s *Multicast) Instantiate(fwThread *Thread) {
	s.NewStrategyBase(fwThread, enc.Component{
		Typ: enc.TypeGenericNameComponent, Val: []byte("multicast"),
	}, 1, "Multicast")
}

func (s *Multicast) AfterContentStoreHit(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.LogTrace(s, "AfterContentStoreHit: Forwarding content store hit Data=", packet.Name, " to FaceID=", inFace)
	s.SendData(packet, pitEntry, inFace, 0) // 0 indicates ContentStore is source
}

func (s *Multicast) AfterReceiveData(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.LogTrace(s, "AfterReceiveData: Data=", packet.Name, ", ", len(pitEntry.InRecords()), " In-Records")
	for faceID := range pitEntry.InRecords() {
		core.LogTrace(s, "AfterReceiveData: Forwarding Data=", packet.Name, " to FaceID=", faceID)
		s.SendData(packet, pitEntry, faceID, inFace)
	}
}

func (s *Multicast) AfterReceiveInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
	nexthops []*table.FibNextHopEntry,
) {
	if len(nexthops) == 0 {
		core.LogDebug(s, "AfterReceiveInterest: No nexthop for Interest=", packet.Name, " - DROP")
		return
	}

	// If there is an out record less than suppression interval ago, drop the
	// retransmission to suppress it (only if the nonce is different)
	for _, outRecord := range pitEntry.OutRecords() {
		if outRecord.LatestNonce != *packet.L3.Interest.Nonce() &&
			outRecord.LatestTimestamp.Add(MulticastSuppressionTime).After(time.Now()) {
			core.LogDebug(s, "AfterReceiveInterest: Suppressed Interest=", packet.Name, " - DROP")
			return
		}
	}

	// Send interest to all nexthops
	for _, nexthop := range nexthops {
		core.LogTrace(s, "AfterReceiveInterest: Forwarding Interest=", packet.Name, " to FaceID=", nexthop.Nexthop)
		s.SendInterest(packet, pitEntry, nexthop.Nexthop, inFace)
	}
}

func (s *Multicast) BeforeSatisfyInterest(pitEntry table.PitEntry, inFace uint64) {
	// This does nothing in Multicast
}
