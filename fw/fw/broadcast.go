/* Broadcast Strategy for ndnd
 *
 * Implements multicast broadcast forwarding as a proper NDN forwarding strategy.
 */

package fw

import (
	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/table"
)

// BroadcastStrategy implements broadcast multicast forwarding.
type BroadcastStrategy struct {
	StrategyBase
}

func init() {
	strategyInit = append(strategyInit, func() Strategy { return &BroadcastStrategy{} })
	StrategyVersions["broadcast"] = []uint64{1}
}

func (s *BroadcastStrategy) Instantiate(fwThread *Thread) {
	s.NewStrategyBase(fwThread, "broadcast", 1)
}

func (s *BroadcastStrategy) AfterContentStoreHit(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.Log.Trace(s, "AfterContentStoreHit", "name", packet.Name, "faceid", inFace)
	s.SendData(packet, pitEntry, inFace, 0)
}

func (s *BroadcastStrategy) AfterReceiveData(
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

func (s *BroadcastStrategy) AfterReceiveInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
	nexthops []StrategyCandidateHop,
) {
	core.Log.Error(s, "BroadcastStrategy does not support AfterReceiveInterest (unicast)",
		"name", packet.Name,
		"inFace", inFace,
		"nexthops", len(nexthops),
	)
}

func (s *BroadcastStrategy) AfterReceiveMulticastInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
	petEntry table.PetEntry,
	deliveredToLocal bool,
) {
	core.Log.Trace(s, "Broadcast multicast dispatch",
		"name", packet.Name,
		"deliveredToLocal", deliveredToLocal,
		"petEgress", len(petEntry.EgressRouters),
		"petNextHops", len(petEntry.NextHops),
	)

	seen := make(map[uint64]struct{})
	sent := 0

	for _, egress := range petEntry.EgressRouters {
		nextHops := table.FibStrategyTable.FindNextHopsEnc(egress)
		core.Log.Trace(s, "Resolved broadcast PET egress",
			"name", packet.Name,
			"egress", egress,
			"fibNextHops", len(nextHops),
		)

		for _, nextHop := range nextHops {
			faceID := nextHop.Nexthop
			if _, ok := seen[faceID]; ok {
				continue
			}
			seen[faceID] = struct{}{}

			if faceID == packet.IncomingFaceID {
				core.Log.Trace(s, "Skipping broadcast face: incoming face",
					"name", packet.Name,
					"faceid", faceID,
					"egress", egress,
				)
				continue
			}

			if pitEntry.InRecords()[faceID] != nil {
				core.Log.Trace(s, "Skipping broadcast face: already pending",
					"name", packet.Name,
					"faceid", faceID,
					"egress", egress,
				)
				continue
			}

			core.Log.Trace(s, "Broadcast forwarding Interest",
				"name", packet.Name,
				"faceid", faceID,
				"egress", egress,
			)
			if s.SendInterest(packet, pitEntry, faceID, inFace) {
				sent++
			}
		}
	}

	if sent == 0 {
		core.Log.Warn(s, "Broadcast multicast had no eligible PET-scoped nexthops",
			"name", packet.Name,
			"deliveredToLocal", deliveredToLocal,
			"petEgress", len(petEntry.EgressRouters),
		)
	}
}

func (s *BroadcastStrategy) BeforeSatisfyInterest(pitEntry table.PitEntry, inFace uint64) {}
