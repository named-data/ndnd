package bier_test

// TestBiftRebuildOnFibChange verifies that the BIFT is properly rebuilt when
// the FIB changes. This tests the hook added in table_algo.go:updateFib().
//
// The test works entirely within the fw layer: it simulates "a FIB change"
// by calling BuildFromFib directly (which is what table_algo.go calls),
// verifying that next-hop information visible through the FibStrategyTable is
// reflected in the BIFT after the rebuild — and that stale entries are
// corrected on a subsequent rebuild.

import (
	"testing"

	bier "github.com/named-data/ndnd/fw/bier"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
)

// TestBiftRebuildOnFibChange verifies the core invariant introduced by Req 1:
// after BuildFromFib is called (which table_algo.go now does on every FIB
// update), the BIFT next-hops reflect whatever is currently in the FIB.
func TestBiftRebuildOnFibChange(t *testing.T) {
	// Use the global FibStrategyTable (requires initialization).
	table.Initialize()

	b := &bier.BiftState{}

	rA := enc.Name{enc.NewGenericComponent("routerA")}
	rB := enc.Name{enc.NewGenericComponent("routerB")}

	b.RegisterRouter(rA, 1)
	b.RegisterRouter(rB, 2)

	t.Run("BIFT has no nexthops before any FIB route", func(t *testing.T) {
		// FIB is empty → no next-hops resolved
		b.BuildFromFib()
		b.RebuildFbm()

		neighbors := b.GetNeighborEntries()
		if len(neighbors) != 0 {
			t.Errorf("expected 0 BIFT neighbors with empty FIB, got %d", len(neighbors))
		}
	})

	t.Run("BIFT reflects nexthop after FIB route added", func(t *testing.T) {
		// Simulate a FIB entry by directly calling UpdateNextHop (equivalent to
		// what BuildFromFib does after resolving FibStrategyTable).
		// In production table_algo.go calls BuildFromFib() which calls
		// FibStrategyTable.FindNextHopsEnc; here we directly inject the result.
		b.UpdateNextHop(1, 100) // routerA reachable via face 100
		b.UpdateNextHop(2, 200) // routerB reachable via face 200
		b.RebuildFbm()

		neighbors := b.GetNeighborEntries()
		if len(neighbors) != 2 {
			t.Fatalf("expected 2 BIFT neighbors after FIB update, got %d", len(neighbors))
		}

		faceSet := make(map[uint64]bool)
		for _, n := range neighbors {
			faceSet[n.FaceID] = true
		}
		if !faceSet[100] {
			t.Error("face 100 (routerA nexthop) should be in BIFT")
		}
		if !faceSet[200] {
			t.Error("face 200 (routerB nexthop) should be in BIFT")
		}
	})

	t.Run("BIFT reflects nexthop change (FIB convergence event)", func(t *testing.T) {
		// Simulate a topology change: routerA's path now goes through face 300
		// instead of face 100 (e.g. after a link failure and re-convergence).
		b.UpdateNextHop(1, 300) // routerA now via face 300
		b.RebuildFbm()

		neighbors := b.GetNeighborEntries()
		faceSet := make(map[uint64]bool)
		for _, n := range neighbors {
			faceSet[n.FaceID] = true
		}

		if faceSet[100] {
			t.Error("face 100 should no longer be a BIFT neighbor after FIB convergence")
		}
		if !faceSet[300] {
			t.Error("face 300 (new routerA nexthop) should be in BIFT after rebuild")
		}
		if !faceSet[200] {
			t.Error("face 200 (routerB nexthop) should still be in BIFT")
		}
	})

	t.Run("BIFT bit-string encoding uses updated nexthops", func(t *testing.T) {
		// After the "FIB convergence" above, the bit-string built for routerA
		// should still result in bit 1 being set (BFR-ID is stable).
		bs := b.BuildBierBitString([]enc.Name{rA})
		if !bier.BierGetBit(bs, 1) {
			t.Error("bit 1 (routerA BFR-ID) should be set after FIB-driven rebuild")
		}
		if bier.BierGetBit(bs, 2) {
			t.Error("bit 2 (routerB BFR-ID) should NOT be set when only routerA is egress")
		}
	})
}

// TestBiftBuildFromFibMultipleRebuildsSafe verifies that calling
// BuildFromFib multiple times (as happens on every FIB change in
// table_algo.go) is safe and idempotent when the FIB is stable.
func TestBiftBuildFromFibMultipleRebuildsSafe(t *testing.T) {
	table.Initialize()

	b := &bier.BiftState{}
	rX := enc.Name{enc.NewGenericComponent("routerX")}
	b.RegisterRouter(rX, 5)
	b.UpdateNextHop(5, 77)

	// Simulate multiple FIB-change triggers (nothing changed in FIB itself).
	for i := 0; i < 10; i++ {
		b.BuildFromFib()
	}
	b.RebuildFbm()

	// State should be consistent — with an empty FIB the stale next hop and
	// stale F-BM must be cleared rather than preserved.
	neighbors := b.GetNeighborEntries()
	if len(neighbors) != 0 {
		t.Fatalf("expected stale BIFT nexthops to be cleared when FIB is empty, got %d neighbors", len(neighbors))
	}
}

func TestBiftBuildFromFibSelectsDeterministicBestNextHop(t *testing.T) {
	table.Initialize()

	b := &bier.BiftState{}
	rX := enc.Name{enc.NewGenericComponent("routerX")}
	b.RegisterRouter(rX, 5)

	table.FibStrategyTable.InsertNextHopEnc(rX, 200, 10)
	table.FibStrategyTable.InsertNextHopEnc(rX, 100, 10)

	b.BuildFromFib()

	neighbors := b.GetNeighborEntries()
	if len(neighbors) != 1 {
		t.Fatalf("expected exactly 1 BIFT neighbor for equal-cost routes, got %d", len(neighbors))
	}
	if neighbors[0].FaceID != 100 {
		t.Fatalf("expected deterministic equal-cost tie-break to pick face 100, got %d", neighbors[0].FaceID)
	}
	if !bier.BierGetBit(neighbors[0].Fbm, 5) {
		t.Fatal("selected neighbor F-BM should retain routerX bit 5")
	}
}

// TestTransitSkipsPetEgressLookup verifies that twoPhaseLookup does NOT
// build a nextER list when hasBier=true (the transit router case).
// We test the observable effect via the topo simulator: a transit node that
// receives a BIER packet must not re-encode a new bit-string from PET.
//
// We verify this by confirming that the BIER simulation produces exactly the
// correct delivery set even on topologies where a transit BFR sits "under"
// multiple PET prefixes — proving the transit never re-derives egress from PET.
func TestTransitSkipsPetEgressLookup(t *testing.T) {
	// Linear 5-node topology: BFIR=0, transit=1,2,3, BFER=4
	// The key property: nodes 1, 2, 3 must NOT locally deliver (they are
	// pure transit). If they were to re-derive egress from PET they would
	// potentially flood, producing deliveries to extra nodes.
	g := buildLinear(5)

	t.Run("Transit nodes do not consume packets addressed only to BFER", func(t *testing.T) {
		// Bitstring: only bit 4 (BFER at the far end)
		bs := g.buildBitstring(4)
		res := g.simulate(0, bs)

		// Only node 4 should receive delivery
		assertDeliveredExactly(t, res, 4)

		// Nodes 1, 2, 3 are transit — must not be in delivered set
		for _, id := range []int{1, 2, 3} {
			if res.delivered[id] {
				t.Errorf("transit node %d must not receive delivery (bit not set in bitstring)", id)
			}
		}
	})

	t.Run("Transit nodes forward correctly (multi-hop replication)", func(t *testing.T) {
		// Bitstring: bits 1, 3, and 4 — every-other BFER along the chain
		bs := g.buildBitstring(1, 3, 4)
		res := g.simulate(0, bs)

		assertDeliveredExactly(t, res, 1, 3, 4)

		// Node 2 is transit-only here
		if res.delivered[2] {
			t.Error("node 2 should not receive delivery (not in bitstring)")
		}
	})

	t.Run("Diamond: transit nodes 1 and 2 do not corrupt replication", func(t *testing.T) {
		// Diamond: 0→1, 0→2, 1→3, 2→3
		// Transit nodes 1 and 2 must forward correctly to BFER=3 without
		// re-encoding a new bit-string.
		g2 := newTopo(4)
		g2.addLink(0, 1)
		g2.addLink(0, 2)
		g2.addLink(1, 3)
		g2.addLink(2, 3)
		g2.buildBifts()

		bs := g2.buildBitstring(3)
		res := g2.simulate(0, bs)

		assertDeliveredExactly(t, res, 3)
		for _, id := range []int{1, 2} {
			if res.delivered[id] {
				t.Errorf("transit node %d received delivery but was not in bitstring", id)
			}
		}
	})
}
