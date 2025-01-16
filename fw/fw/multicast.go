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
)

// MulticastSuppressionTime is the time to suppress retransmissions of the same Interest.
const MulticastSuppressionTime = 500 * time.Millisecond

// Multicast is a forwarding strategy that forwards Interests to all nexthop faces.
type Multicast struct {
	StrategyBase
}

func init() {
	strategyInit = append(strategyInit, func() Strategy { return &Multicast{} })
	StrategyVersions["multicast"] = []uint64{1}
}

func (s *Multicast) Instantiate(fwThread *Thread) {
	s.NewStrategyBase(fwThread, "multicast", 1)
}

func (s *Multicast) AfterContentStoreHit(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.Log.Trace(s, "AfterContentStoreHit", "name", packet.Name, "faceid", inFace)
	s.SendData(packet, pitEntry, inFace, 0) // 0 indicates ContentStore is source
}

func (s *Multicast) AfterReceiveData(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.Log.Trace(s, "AfterReceiveData", "name", packet.Name, "inrecords", len(pitEntry.InRecords()))
	for faceID := range pitEntry.InRecords() {
		core.Log.Trace(s, "Forwarding Data", "name", packet.Name, "faceid", faceID)
		s.SendData(packet, pitEntry, faceID, inFace)
	}
}

func (s *Multicast) AfterReceiveInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
	nexthops [defn.MaxNextHops]*table.FibNextHopEntry,
	nexthopsCount int,
) {
	if len(nexthops) == 0 {
		core.Log.Debug(s, "No nexthop for Interest", "name", packet.Name)
		return
	}

	// If there is an out record less than suppression interval ago, drop the
	// retransmission to suppress it (only if the nonce is different)
	for _, outRecord := range pitEntry.OutRecords() {
		if outRecord.LatestNonce != *packet.L3.Interest.Nonce() &&
			outRecord.LatestTimestamp.Add(MulticastSuppressionTime).After(time.Now()) {
			core.Log.Debug(s, "Suppressed Interest", "name", packet.Name)
			return
		}
	}

	// Send interest to all nexthops
	for _, nexthop := range nexthops {
		core.Log.Trace(s, "Forwarding Interest", "name", packet.Name, "faceid", nexthop.Nexthop)
		s.SendInterest(packet, pitEntry, nexthop.Nexthop, inFace)
	}
}

func (s *Multicast) BeforeSatisfyInterest(pitEntry table.PitEntry, inFace uint64) {
	// This does nothing in Multicast
}
