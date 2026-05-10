/* BIER replication helpers for ndnd
 *
 * Provides bierReplicate function for BIFT-based BIER multicast forwarding.
 * Called directly from thread.go's handleMulticastPipeline - no strategy needed.
 */

package fw

import (
	"github.com/named-data/ndnd/fw/bier"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/table"
	ndnlog "github.com/named-data/ndnd/std/log"
)

// bierReplicate performs BIFT-based BIER replication through the PIT.
// Local bit is cleared first (local delivery already done by thread.go).
// Remaining bits are replicated to BIFT neighbors using sendInterest,
// which creates PIT out-records for Data return path tracking.
func bierReplicate(
	logCtx ndnlog.Tag,
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
	sendInterest func(*defn.Pkt, table.PitEntry, uint64, uint64) bool,
) {
	incomingBs := bier.BierClone(packet.Bier)

	// Clear local bit — local delivery was already handled by thread.go.
	// Also clear it if no local app is registered, to avoid forwarding our
	// own bit position to downstream neighbors.
	if bier.IsBierEnabled() {
		localId := bier.CfgBierIndex()
		if localId >= 0 && bier.BierGetBit(incomingBs, localId) {
			bier.BierClearBit(incomingBs, localId)
		}
	}

	if bier.BierIsZero(incomingBs) {
		return
	}

	neighbors := bier.Bift.GetNeighborEntries()
	for _, neighbor := range neighbors {
		if neighbor.FaceID == inFace {
			continue // Never send back on incoming face
		}

		replicationMask := bier.BierAnd(incomingBs, neighbor.Fbm)
		if bier.BierIsZero(replicationMask) {
			continue
		}

		// Clone packet with per-neighbor replication mask
		clonePkt := &defn.Pkt{
			Name:           packet.Name,
			L3:             packet.L3,
			Raw:            packet.Raw,
			IncomingFaceID: packet.IncomingFaceID,
			CongestionMark: packet.CongestionMark,
			Bier:           replicationMask,
		}

		// SendInterest creates PIT out-record — Data return path is tracked
		sendInterest(clonePkt, pitEntry, neighbor.FaceID, inFace)

		// Loop suppression: clear forwarded bits from working mask
		incomingBs = bier.BierAndNot(incomingBs, neighbor.Fbm)
		if bier.BierIsZero(incomingBs) {
			break
		}
	}
}
