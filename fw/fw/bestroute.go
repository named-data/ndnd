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

const BestRouteSuppressionTime = 500 * time.Millisecond

// BestRoute is a forwarding strategy that forwards Interests
// to the nexthop with the lowest cost.
type BestRoute struct {
	StrategyBase
}

func init() {
	strategyTypes = append(strategyTypes, func() Strategy {
		return &BestRoute{}
	})
	StrategyVersions["best-route"] = []uint64{1}
}

func (s *BestRoute) Instantiate(fwThread *Thread) {
	s.NewStrategyBase(fwThread, enc.Component{
		Typ: enc.TypeGenericNameComponent, Val: []byte("best-route"),
	}, 1, "BestRoute")
}

func (s *BestRoute) AfterContentStoreHit(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.LogTrace(s, "AfterContentStoreHit: Forwarding content store hit Data=", packet.Name, " to FaceID=", inFace)
	s.SendData(packet, pitEntry, inFace, 0) // 0 indicates ContentStore is source
}

func (s *BestRoute) AfterReceiveData(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.LogTrace(s, "AfterReceiveData: Data=", ", ", len(pitEntry.InRecords()), " In-Records")
	for faceID := range pitEntry.InRecords() {
		core.LogTrace(s, "AfterReceiveData: Forwarding Data=", packet.Name, " to FaceID=", faceID)
		s.SendData(packet, pitEntry, faceID, inFace)
	}
}

func (s *BestRoute) AfterReceiveInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
	nexthops [MaxNextHops]*table.FibNextHopEntry,
	nexthopsCount int,
) {
	if nexthopsCount == 0 {
		if core.HasDebugLogs() {
			core.LogDebug(s, "AfterReceiveInterest: No nexthop for Interest=", packet.Name, " - DROP")
		}
		return
	}

	// If there is an out record less than suppression interval ago, drop the
	// retransmission to suppress it (only if the nonce is different)
	for _, outRecord := range pitEntry.OutRecords() {
		if outRecord.LatestNonce != *packet.L3.Interest.Nonce() &&
			outRecord.LatestTimestamp.Add(BestRouteSuppressionTime).After(time.Now()) {
			if core.HasDebugLogs() {
				core.LogDebug(s, "AfterReceiveInterest: Suppressed Interest=", packet.Name, " - DROP")
			}
			return
		}
	}

	// Sort nexthops by cost and send to best-possible nexthop
	lowesthops := nexthops
	getLowest := func() *table.FibNextHopEntry {
		cost := uint64(1 << 63)
		index := -1
		for i := 0; i < nexthopsCount; i++ {
			nh := nexthops[i]
			if nh == nil {
				continue
			}
			if nh.Cost < cost {
				cost = nh.Cost
				index = i
			}
		}
		if index == -1 {
			return nil
		}
		hop := nexthops[index]
		lowesthops[index] = nil
		return hop
	}

	for nh := getLowest(); nh != nil; nh = getLowest() {
		if core.HasTraceLogs() {
			core.LogTrace(s, "AfterReceiveInterest: Forwarding Interest=", packet.Name, " to FaceID=", nh.Nexthop)
		}
		if sent := s.SendInterest(packet, pitEntry, nh.Nexthop, inFace); sent {
			return
		}
	}

	if core.HasDebugLogs() {
		core.LogDebug(s, "AfterReceiveInterest: No usable nexthop for Interest=", packet.Name, " - DROP")
	}
}

func (s *BestRoute) BeforeSatisfyInterest(pitEntry table.PitEntry, inFace uint64) {
	// This does nothing in BestRoute
}
