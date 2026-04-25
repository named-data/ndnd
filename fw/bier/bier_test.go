package bier_test

import (
	"testing"

	bier "github.com/named-data/ndnd/fw/bier"
	enc "github.com/named-data/ndnd/std/encoding"
)

// TestBierBitManipulation tests the BIER bit manipulation helper functions
func TestBierBitManipulation(t *testing.T) {
	t.Run("SetBit and GetBit", func(t *testing.T) {
		var bs []byte

		// Set bits 0, 5, 15
		bs = bier.BierSetBit(bs, 0)
		bs = bier.BierSetBit(bs, 5)
		bs = bier.BierSetBit(bs, 15)

		// Check that bits are set correctly
		if !bier.BierGetBit(bs, 0) {
			t.Error("Bit 0 should be set")
		}
		if !bier.BierGetBit(bs, 5) {
			t.Error("Bit 5 should be set")
		}
		if !bier.BierGetBit(bs, 15) {
			t.Error("Bit 15 should be set")
		}

		// Check that other bits are not set
		if bier.BierGetBit(bs, 1) {
			t.Error("Bit 1 should not be set")
		}
		if bier.BierGetBit(bs, 7) {
			t.Error("Bit 7 should not be set")
		}
	})

	t.Run("ClearBit", func(t *testing.T) {
		bs := []byte{0xFF, 0xFF} // All bits set in first two bytes

		bier.BierClearBit(bs, 3)
		bier.BierClearBit(bs, 10)

		if bier.BierGetBit(bs, 3) {
			t.Error("Bit 3 should be cleared")
		}
		if bier.BierGetBit(bs, 10) {
			t.Error("Bit 10 should be cleared")
		}
		if !bier.BierGetBit(bs, 2) {
			t.Error("Bit 2 should still be set")
		}
		if !bier.BierGetBit(bs, 9) {
			t.Error("Bit 9 should still be set")
		}
	})

	t.Run("bier.BierAnd", func(t *testing.T) {
		a := []byte{0b11110000, 0b10101010}
		b := []byte{0b11001100, 0b11110000}

		result := bier.BierAnd(a, b)
		expected := []byte{0b11000000, 0b10100000}

		if len(result) != len(expected) {
			t.Errorf("Result length mismatch: got %d, want %d", len(result), len(expected))
		}
		for i := range expected {
			if result[i] != expected[i] {
				t.Errorf("Byte %d: got %08b, want %08b", i, result[i], expected[i])
			}
		}
	})

	t.Run("bier.BierAndNot", func(t *testing.T) {
		a := []byte{0b11111111, 0b11111111}
		b := []byte{0b00001111, 0b11110000}

		result := bier.BierAndNot(a, b)
		expected := []byte{0b11110000, 0b00001111}

		if len(result) != len(expected) {
			t.Errorf("Result length mismatch: got %d, want %d", len(result), len(expected))
		}
		for i := range expected {
			if result[i] != expected[i] {
				t.Errorf("Byte %d: got %08b, want %08b", i, result[i], expected[i])
			}
		}
	})

	t.Run("bier.BierIsZero", func(t *testing.T) {
		zero := []byte{0, 0, 0}
		nonZero := []byte{0, 0, 1}

		if !bier.BierIsZero(zero) {
			t.Error("Zero bitstring should return true")
		}
		if bier.BierIsZero(nonZero) {
			t.Error("Non-zero bitstring should return false")
		}
	})

	t.Run("bier.BierClone", func(t *testing.T) {
		original := []byte{1, 2, 3, 4}
		cloned := bier.BierClone(original)

		if len(cloned) != len(original) {
			t.Errorf("Clone length mismatch: got %d, want %d", len(cloned), len(original))
		}

		// Verify contents are identical
		for i := range original {
			if cloned[i] != original[i] {
				t.Errorf("Byte %d: got %d, want %d", i, cloned[i], original[i])
			}
		}

		// Verify it's a deep copy
		cloned[0] = 99
		if original[0] == 99 {
			t.Error("Modifying clone should not affect original")
		}
	})
}

// TestBiftConstruction tests the BIFT construction and lookup
func TestBiftConstruction(t *testing.T) {
	bift := &bier.BiftState{}

	t.Run("RegisterRouter", func(t *testing.T) {
		r1 := enc.Name{enc.NewGenericComponent("router1")}
		r2 := enc.Name{enc.NewGenericComponent("router2")}
		r3 := enc.Name{enc.NewGenericComponent("router3")}

		bift.RegisterRouter(r1, 0)
		bift.RegisterRouter(r2, 1)
		bift.RegisterRouter(r3, 5)

		// Verify lookups
		id1, ok1 := bift.GetRouterBfrId(r1)
		if !ok1 || id1 != 0 {
			t.Errorf("Router1 BFR-ID: got %d, want 0", id1)
		}

		id2, ok2 := bift.GetRouterBfrId(r2)
		if !ok2 || id2 != 1 {
			t.Errorf("Router2 BFR-ID: got %d, want 1", id2)
		}

		id3, ok3 := bift.GetRouterBfrId(r3)
		if !ok3 || id3 != 5 {
			t.Errorf("Router3 BFR-ID: got %d, want 5", id3)
		}

		// Test non-existent router
		r4 := enc.Name{enc.NewGenericComponent("router4")}
		_, ok4 := bift.GetRouterBfrId(r4)
		if ok4 {
			t.Error("Non-existent router should return false")
		}
	})

	t.Run("BuildBierBitString", func(t *testing.T) {
		r1 := enc.Name{enc.NewGenericComponent("router1")}
		r2 := enc.Name{enc.NewGenericComponent("router2")}
		r3 := enc.Name{enc.NewGenericComponent("router3")}

		bift.RegisterRouter(r1, 0)
		bift.RegisterRouter(r2, 1)
		bift.RegisterRouter(r3, 5)

		// Build bit-string for routers 1 and 3
		egressRouters := []enc.Name{r1, r3}
		bs := bift.BuildBierBitString(egressRouters)

		// Check that bits 0 and 5 are set
		if !bier.BierGetBit(bs, 0) {
			t.Error("Bit 0 (router1) should be set")
		}
		if !bier.BierGetBit(bs, 5) {
			t.Error("Bit 5 (router3) should be set")
		}
		if bier.BierGetBit(bs, 1) {
			t.Error("Bit 1 (router2) should not be set")
		}
	})

	t.Run("UpdateNextHop and RebuildFbm", func(t *testing.T) {
		r1 := enc.Name{enc.NewGenericComponent("router1")}
		r2 := enc.Name{enc.NewGenericComponent("router2")}
		r3 := enc.Name{enc.NewGenericComponent("router3")}

		bift.RegisterRouter(r1, 0)
		bift.RegisterRouter(r2, 1)
		bift.RegisterRouter(r3, 5)

		// Set next hops - routers 1 and 2 via face 100, router 3 via face 200
		bift.UpdateNextHop(0, 100)
		bift.UpdateNextHop(1, 100)
		bift.UpdateNextHop(5, 200)

		bift.RebuildFbm()

		// Get neighbor entries
		neighbors := bift.GetNeighborEntries()

		// Should have 2 neighbor entries (face 100 and face 200)
		if len(neighbors) != 2 {
			t.Errorf("Expected 2 neighbor entries, got %d", len(neighbors))
		}

		// Find face 100 entry and verify its F-BM has bits 0 and 1 set
		var face100Fbm []byte
		var face200Fbm []byte
		for _, n := range neighbors {
			if n.FaceID == 100 {
				face100Fbm = n.Fbm
			} else if n.FaceID == 200 {
				face200Fbm = n.Fbm
			}
		}

		if face100Fbm == nil {
			t.Error("Face 100 neighbor entry not found")
		} else {
			if !bier.BierGetBit(face100Fbm, 0) {
				t.Error("Face 100 F-BM should have bit 0 set")
			}
			if !bier.BierGetBit(face100Fbm, 1) {
				t.Error("Face 100 F-BM should have bit 1 set")
			}
			if bier.BierGetBit(face100Fbm, 5) {
				t.Error("Face 100 F-BM should not have bit 5 set")
			}
		}

		if face200Fbm == nil {
			t.Error("Face 200 neighbor entry not found")
		} else {
			if !bier.BierGetBit(face200Fbm, 5) {
				t.Error("Face 200 F-BM should have bit 5 set")
			}
			if bier.BierGetBit(face200Fbm, 0) {
				t.Error("Face 200 F-BM should not have bit 0 set")
			}
		}
	})

	t.Run("Status", func(t *testing.T) {
		snapshot := &bier.BiftState{}
		r0 := enc.Name{enc.NewGenericComponent("router0")}
		r1 := enc.Name{enc.NewGenericComponent("router1")}
		r5 := enc.Name{enc.NewGenericComponent("router5")}

		snapshot.RegisterRouter(r5, 5)
		snapshot.RegisterRouter(r1, 1)
		snapshot.RegisterRouter(r0, 0)
		snapshot.UpdateNextHop(5, 200)
		snapshot.UpdateNextHop(1, 100)
		snapshot.UpdateNextHop(0, 100)
		snapshot.RebuildFbm()

		status := snapshot.Status()
		if len(status.Entries) != 3 {
			t.Fatalf("Expected 3 status entries, got %d", len(status.Entries))
		}
		if status.Entries[0].BfrId != 0 || status.Entries[1].BfrId != 1 || status.Entries[2].BfrId != 5 {
			t.Fatalf("Status entries not sorted by BFR-ID: %+v", status.Entries)
		}
		if status.Entries[0].RouterName != r0.String() {
			t.Fatalf("Unexpected router name for index 0: got %s want %s", status.Entries[0].RouterName, r0)
		}
		if len(status.Entries[0].NextHops) != 1 || status.Entries[0].NextHops[0] != 100 {
			t.Fatalf("Unexpected next-hops for index 0: %+v", status.Entries[0].NextHops)
		}
		if len(status.Entries[0].FbmBits) != 2 || status.Entries[0].FbmBits[0] != 0 || status.Entries[0].FbmBits[1] != 1 {
			t.Fatalf("Unexpected F-BM bits for index 0: %+v", status.Entries[0].FbmBits)
		}
		if len(status.Entries[2].NextHops) != 1 || status.Entries[2].NextHops[0] != 200 {
			t.Fatalf("Unexpected next-hops for index 5: %+v", status.Entries[2].NextHops)
		}
		if len(status.Entries[2].FbmBits) != 1 || status.Entries[2].FbmBits[0] != 5 {
			t.Fatalf("Unexpected F-BM bits for index 5: %+v", status.Entries[2].FbmBits)
		}

		if len(status.Neighbors) != 2 {
			t.Fatalf("Expected 2 BIFT neighbors, got %d", len(status.Neighbors))
		}
		if status.Neighbors[0].FaceID != 100 || status.Neighbors[1].FaceID != 200 {
			t.Fatalf("Neighbors not sorted by face ID: %+v", status.Neighbors)
		}
		if len(status.Neighbors[0].FbmBits) != 2 || status.Neighbors[0].FbmBits[0] != 0 || status.Neighbors[0].FbmBits[1] != 1 {
			t.Fatalf("Unexpected neighbor F-BM bits for face 100: %+v", status.Neighbors[0].FbmBits)
		}
		if len(status.Neighbors[1].FbmBits) != 1 || status.Neighbors[1].FbmBits[0] != 5 {
			t.Fatalf("Unexpected neighbor F-BM bits for face 200: %+v", status.Neighbors[1].FbmBits)
		}
	})
}

// TestBierReplicationMask tests the replication mask computation
func TestBierReplicationMask(t *testing.T) {
	// Simulate a scenario where we have 3 downstream neighbors
	// Neighbor 1 can reach routers at bits 0, 1, 2
	// Neighbor 2 can reach routers at bits 3, 4
	// Neighbor 3 can reach routers at bits 5, 6

	var fbm1, fbm2, fbm3 []byte
	fbm1 = bier.BierSetBit(fbm1, 0)
	fbm1 = bier.BierSetBit(fbm1, 1)
	fbm1 = bier.BierSetBit(fbm1, 2)

	fbm2 = bier.BierSetBit(fbm2, 3)
	fbm2 = bier.BierSetBit(fbm2, 4)

	fbm3 = bier.BierSetBit(fbm3, 5)
	fbm3 = bier.BierSetBit(fbm3, 6)

	// Incoming BIER bit-string has bits 0, 3, 5 set (3 egress routers)
	var incoming []byte
	incoming = bier.BierSetBit(incoming, 0)
	incoming = bier.BierSetBit(incoming, 3)
	incoming = bier.BierSetBit(incoming, 5)

	// Compute replication masks
	rep1 := bier.BierAnd(incoming, fbm1)
	rep2 := bier.BierAnd(incoming, fbm2)
	rep3 := bier.BierAnd(incoming, fbm3)

	// Neighbor 1 should replicate for bit 0 only
	if !bier.BierGetBit(rep1, 0) {
		t.Error("Neighbor 1 should replicate for bit 0")
	}
	if bier.BierGetBit(rep1, 1) || bier.BierGetBit(rep1, 2) {
		t.Error("Neighbor 1 should not replicate for bits 1 or 2")
	}

	// Neighbor 2 should replicate for bit 3 only
	if !bier.BierGetBit(rep2, 3) {
		t.Error("Neighbor 2 should replicate for bit 3")
	}
	if bier.BierGetBit(rep2, 4) {
		t.Error("Neighbor 2 should not replicate for bit 4")
	}

	// Neighbor 3 should replicate for bit 5 only
	if !bier.BierGetBit(rep3, 5) {
		t.Error("Neighbor 3 should replicate for bit 5")
	}
	if bier.BierGetBit(rep3, 6) {
		t.Error("Neighbor 3 should not replicate for bit 6")
	}
}
