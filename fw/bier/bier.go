/* BIER - Bit Index Explicit Replication for ndnd
 *
 * Stateless multicast forwarding using bit-indexed replication.
 * Each router is assigned a unique BFR-ID (bit index) by the operator.
 * The BIFT maps each bit position to a next-hop face and forwarding bit mask.
 */

package bier

import (
	"sort"
	"sync"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
)

// BiftEntry represents a single entry in the Bit Index Forwarding Table.
// Each entry maps a BFR-ID (bit position) to a next-hop face and
// the forwarding bit mask (F-BM) for that neighbor.
type BiftEntry struct {
	BfrId      int      // Bit position this entry is for
	RouterName enc.Name // Name of the destination router
	NextHop    uint64   // Face ID to reach this router's next hop
	Fbm        []byte   // Forwarding Bit Mask for this neighbor
}

// BiftStatusEntry is a JSON-friendly snapshot of one BIFT entry.
type BiftStatusEntry struct {
	BfrId      int      `json:"bfr_id"`
	RouterName string   `json:"router_name"`
	NextHops   []uint64 `json:"next_hops"`
	FbmBits    []int    `json:"fbm_bits"`
}

// BiftStatusNeighbor is a JSON-friendly snapshot of one BIFT neighbor entry.
type BiftStatusNeighbor struct {
	FaceID  uint64 `json:"face_id"`
	FbmBits []int  `json:"fbm_bits"`
}

// BiftStatus is a JSON-friendly snapshot of the current BIFT state.
type BiftStatus struct {
	BierIndex int                  `json:"bier_index"`
	Entries   []BiftStatusEntry    `json:"entries"`
	Neighbors []BiftStatusNeighbor `json:"neighbors"`
}

// Bift is the global Bit Index Forwarding Table.
var Bift = &BiftState{}

// BiftState holds the current BIFT and mapping state.
type BiftState struct {
	mu      sync.RWMutex
	entries map[int]*BiftEntry // BFR-ID -> entry

	// routerBit maps router name hash -> BFR-ID for quick lookup
	routerBit map[uint64]int
}

func (b *BiftState) String() string {
	return "bift"
}

// CfgBierIndex returns the configured BIER index for this router.
// Returns -1 if BIER is not configured (disabled).
func CfgBierIndex() int {
	return core.C.Fw.BierIndex
}

// IsBierEnabled returns true if BIER forwarding is enabled on this router.
func IsBierEnabled() bool {
	return CfgBierIndex() >= 0
}

// --- Bit-string manipulation helpers ---

// BierGetBit returns true if bit position pos is set in the bitstring.
// Bit 0 is the LSB of the first byte.
func BierGetBit(bs []byte, pos int) bool {
	byteIdx := pos / 8
	if byteIdx >= len(bs) {
		return false
	}
	bitIdx := uint(pos % 8)
	return (bs[byteIdx] & (1 << bitIdx)) != 0
}

// BierSetBit sets bit position pos in the bitstring.
// Grows the slice if needed.
func BierSetBit(bs []byte, pos int) []byte {
	byteIdx := pos / 8
	for byteIdx >= len(bs) {
		bs = append(bs, 0)
	}
	bitIdx := uint(pos % 8)
	bs[byteIdx] |= (1 << bitIdx)
	return bs
}

// BierClearBit clears bit position pos in the bitstring.
func BierClearBit(bs []byte, pos int) {
	byteIdx := pos / 8
	if byteIdx >= len(bs) {
		return
	}
	bitIdx := uint(pos % 8)
	bs[byteIdx] &^= (1 << bitIdx)
}

// BierAnd returns bitwise AND of two bitstrings. Result length = max(len(a), len(b)).
func BierAnd(a, b []byte) []byte {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	result := make([]byte, maxLen)
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		result[i] = a[i] & b[i]
	}
	return result
}

// BierOr returns bitwise OR of two bitstrings. Result length = max(len(a), len(b)).
func BierOr(a, b []byte) []byte {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	result := make([]byte, maxLen)
	copy(result, a)
	for i := 0; i < len(b); i++ {
		result[i] |= b[i]
	}
	return result
}

// BierAndNot returns a &^ b (a AND NOT b). Result length = max(len(a), len(b)).
func BierAndNot(a, b []byte) []byte {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	result := make([]byte, maxLen)
	copy(result, a)
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		result[i] = a[i] &^ b[i]
	}
	return result
}

// BierIsZero returns true if all bits in the bitstring are zero.
func BierIsZero(bs []byte) bool {
	for _, b := range bs {
		if b != 0 {
			return false
		}
	}
	return true
}

// BierClone returns a copy of the bitstring.
func BierClone(bs []byte) []byte {
	if bs == nil {
		return nil
	}
	c := make([]byte, len(bs))
	copy(c, bs)
	return c
}

// --- BIFT Construction ---

// RegisterBierRouter registers a router name with its operator-assigned BFR-ID.
// This is called when learning about a router's BIER index (e.g., from DV).
func (b *BiftState) RegisterRouter(routerName enc.Name, bfrId int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.entries == nil {
		b.entries = make(map[int]*BiftEntry)
		b.routerBit = make(map[uint64]int)
	}

	b.entries[bfrId] = &BiftEntry{
		BfrId:      bfrId,
		RouterName: routerName.Clone(),
	}
	b.routerBit[routerName.Hash()] = bfrId

	core.Log.Info(b, "Registered BIER router", "name", routerName, "bfr-id", bfrId)
}

// UpdateNextHop updates the next-hop face for reaching a given BFR-ID.
// Called when FIB changes.
func (b *BiftState) UpdateNextHop(bfrId int, nextHop uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if entry, ok := b.entries[bfrId]; ok {
		entry.NextHop = nextHop
	}
}

// rebuildFbmLocked rebuilds forwarding bit masks for all BIFT entries.
// Caller must hold b.mu.
func (b *BiftState) rebuildFbmLocked() {
	// Find maximum BFR-ID to size bitstrings
	maxBit := 0
	for bfrId := range b.entries {
		if bfrId > maxBit {
			maxBit = bfrId
		}
	}
	bsLen := (maxBit / 8) + 1

	// Group by next-hop face
	faceGroups := make(map[uint64][]int) // faceID -> list of BFR-IDs
	for bfrId, entry := range b.entries {
		if entry.NextHop > 0 {
			faceGroups[entry.NextHop] = append(faceGroups[entry.NextHop], bfrId)
		}
	}

	// Build F-BM for each face group
	faceFbm := make(map[uint64][]byte)
	for faceID, bfrIds := range faceGroups {
		fbm := make([]byte, bsLen)
		for _, id := range bfrIds {
			fbm = BierSetBit(fbm, id)
		}
		faceFbm[faceID] = fbm
	}

	// Assign F-BM to each entry based on its next-hop face
	for _, entry := range b.entries {
		if fbm, ok := faceFbm[entry.NextHop]; ok {
			entry.Fbm = fbm
		}
	}

	core.Log.Info(b, "Rebuilt BIFT forwarding bit masks",
		"entries", len(b.entries), "faces", len(faceGroups))
}

// RebuildFbm rebuilds forwarding bit masks for all BIFT entries.
// Groups BFR-IDs by their next-hop face and computes the F-BM for each group.
func (b *BiftState) RebuildFbm() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rebuildFbmLocked()
}

// BuildFromFib rebuilds the BIFT from the current FIB state.
// For each known router (registered via DV), looks up the FIB to find next hops.
func (b *BiftState) BuildFromFib() {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Update next hops from FIB for each registered router
	for _, entry := range b.entries {
		nexthops := table.FibStrategyTable.FindNextHopsEnc(entry.RouterName)
		if len(nexthops) > 0 {
			// Sort by cost and pick best
			sort.Slice(nexthops, func(i, j int) bool {
				return nexthops[i].Cost < nexthops[j].Cost
			})
			entry.NextHop = nexthops[0].Nexthop
		}
	}

	b.rebuildFbmLocked()
}

func bitPositions(bs []byte) []int {
	positions := make([]int, 0)
	for byteIdx, value := range bs {
		if value == 0 {
			continue
		}
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			if value&(1<<uint(bitIdx)) != 0 {
				positions = append(positions, (byteIdx*8)+bitIdx)
			}
		}
	}
	return positions
}

// Status returns a deterministic snapshot of the current BIFT state.
func (b *BiftState) Status() BiftStatus {
	b.mu.RLock()
	entries := make([]*BiftEntry, 0, len(b.entries))
	for _, entry := range b.entries {
		cloned := *entry
		cloned.RouterName = entry.RouterName.Clone()
		cloned.Fbm = BierClone(entry.Fbm)
		entries = append(entries, &cloned)
	}
	b.mu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].BfrId < entries[j].BfrId
	})

	status := BiftStatus{
		BierIndex: CfgBierIndex(),
		Entries:   make([]BiftStatusEntry, 0, len(entries)),
	}
	for _, entry := range entries {
		nextHops := make([]uint64, 0, 1)
		if entry.NextHop > 0 {
			nextHops = append(nextHops, entry.NextHop)
		}
		status.Entries = append(status.Entries, BiftStatusEntry{
			BfrId:      entry.BfrId,
			RouterName: entry.RouterName.String(),
			NextHops:   nextHops,
			FbmBits:    bitPositions(entry.Fbm),
		})
	}

	neighbors := b.GetNeighborEntries()
	sort.Slice(neighbors, func(i, j int) bool {
		return neighbors[i].FaceID < neighbors[j].FaceID
	})
	status.Neighbors = make([]BiftStatusNeighbor, 0, len(neighbors))
	for _, neighbor := range neighbors {
		status.Neighbors = append(status.Neighbors, BiftStatusNeighbor{
			FaceID:  neighbor.FaceID,
			FbmBits: bitPositions(neighbor.Fbm),
		})
	}

	return status
}

// GetRouterBfrId returns the BFR-ID for a given router name.
func (b *BiftState) GetRouterBfrId(routerName enc.Name) (int, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if id, ok := b.routerBit[routerName.Hash()]; ok {
		return id, true
	}
	return -1, false
}

// --- BFIR Functions ---

// BuildBierBitString builds a BIER bit-string from a list of egress router names.
// Returns nil if no egress routers have known BFR-IDs.
func (b *BiftState) BuildBierBitString(egressRouters []enc.Name) []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var bs []byte
	for _, er := range egressRouters {
		if id, ok := b.routerBit[er.Hash()]; ok {
			bs = BierSetBit(bs, id)
		}
	}
	return bs
}

// --- Replication (BFR/BFER) ---

// BiftNeighborEntry represents a unique next-hop face and its aggregated F-BM.
type BiftNeighborEntry struct {
	FaceID uint64
	Fbm    []byte
}

// GetNeighborEntries returns the unique neighbor entries (grouped by face) from the BIFT.
func (b *BiftState) GetNeighborEntries() []BiftNeighborEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	faceMap := make(map[uint64][]byte)
	for _, entry := range b.entries {
		if entry.NextHop == 0 || entry.Fbm == nil {
			continue
		}
		if fbm, ok := faceMap[entry.NextHop]; ok {
			faceMap[entry.NextHop] = BierOr(fbm, entry.Fbm)
		} else {
			faceMap[entry.NextHop] = BierClone(entry.Fbm)
		}
	}

	neighbors := make([]BiftNeighborEntry, 0, len(faceMap))
	for faceID, fbm := range faceMap {
		neighbors = append(neighbors, BiftNeighborEntry{FaceID: faceID, Fbm: fbm})
	}
	sort.Slice(neighbors, func(i, j int) bool {
		return neighbors[i].FaceID < neighbors[j].FaceID
	})
	return neighbors
}
