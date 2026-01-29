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

// (AI GENERATED DESCRIPTION): Registers the Multicast strategy by appending its constructor to the global strategy initialization list and associating the version “1” with the “multicast” key.
func init() {
	strategyInit = append(strategyInit, func() Strategy { return &Multicast{} })
	StrategyVersions["multicast"] = []uint64{1}
}

// (AI GENERATED DESCRIPTION): Initializes the multicast strategy by setting up its base with the supplied thread, assigning it the name “multicast” and version 1.
func (s *Multicast) Instantiate(fwThread *Thread) {
	s.NewStrategyBase(fwThread, "multicast", 1)
}

// (AI GENERATED DESCRIPTION): Sends the cached Data packet to the originating face after a content‑store hit.
func (s *Multicast) AfterContentStoreHit(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.Log.Trace(s, "AfterContentStoreHit", "name", packet.Name, "faceid", inFace)
	s.SendData(packet, pitEntry, inFace, 0) // 0 indicates ContentStore is source
}

// (AI GENERATED DESCRIPTION): For each face recorded in the PIT entry, forwards the received Data packet to that face while logging the forwarding action.
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

// (AI GENERATED DESCRIPTION): Handles a received multicast Interest by suppressing retransmissions that fall within a defined suppression interval and otherwise forwarding the Interest to all applicable next‑hops.
func (s *Multicast) AfterReceiveInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
	nexthops []*table.FibNextHopEntry,
) {
	if len(nexthops) == 0 {
		core.Log.Debug(s, "No nexthop for Interest", "name", packet.Name)
		return
	}

	// If there is an out record less than suppression interval ago, drop the
	// retransmission to suppress it (only if the nonce is different)
	now := time.Now()
	for _, outRecord := range pitEntry.OutRecords() {
		if outRecord.LatestNonce != packet.L3.Interest.NonceV.Unwrap() &&
			outRecord.LatestTimestamp.Add(MulticastSuppressionTime).After(now) {
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

// (AI GENERATED DESCRIPTION): No‑op hook invoked before satisfying an Interest in the Multicast strategy – it performs no action.
func (s *Multicast) BeforeSatisfyInterest(pitEntry table.PitEntry, inFace uint64) {
	// This does nothing in Multicast
}
