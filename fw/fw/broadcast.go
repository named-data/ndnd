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
	if len(nexthops) == 0 {
		core.Log.Debug(s, "No nexthop found - DROP", "name", packet.Name)
		return
	}
	for _, nh := range nexthops {
		core.Log.Trace(s, "Forwarding Interest", "name", packet.Name, "faceid", nh.HopEntry.Nexthop)
		// if there is an associated EgressRouter tag with this new route, then set packet.EgressRouter to the tag
		if nh.EgressRouter != nil {
			packet.EgressRouter = nh.EgressRouter
			s.SendInterest(packet, pitEntry, nh.HopEntry.Nexthop, inFace)
			// otherwise, normal forwarding
		} else {
			s.SendInterest(packet, pitEntry, nh.HopEntry.Nexthop, inFace)
		}
	}
}

func (s *BroadcastStrategy) BeforeSatisfyInterest(pitEntry table.PitEntry, inFace uint64) {}
