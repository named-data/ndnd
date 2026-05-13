package bier_test

import (
	"sync"
	"testing"

	bier "github.com/named-data/ndnd/fw/bier"
	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
)

// setBierIndex sets the global BierIndex config for test duration.
func setBierIndex(idx int) func() {
	old := core.C.Fw.BierIndex
	core.C.Fw.BierIndex = idx
	return func() { core.C.Fw.BierIndex = old }
}

// --- Bit-manipulation edge cases ---

func TestBierBitManipulationEdgeCases(t *testing.T) {
	t.Run("GetBit on empty slice returns false", func(t *testing.T) {
		if bier.BierGetBit(nil, 0) {
			t.Error("GetBit on nil should be false")
		}
		if bier.BierGetBit([]byte{}, 7) {
			t.Error("GetBit on empty slice should be false")
		}
	})

	t.Run("GetBit out-of-bounds returns false", func(t *testing.T) {
		bs := []byte{0xFF} // only byte 0
		if bier.BierGetBit(bs, 8) {
			t.Error("GetBit at byte 1 of 1-byte slice should be false")
		}
		if bier.BierGetBit(bs, 100) {
			t.Error("GetBit far out of bounds should be false")
		}
	})

	t.Run("SetBit auto-extends slice", func(t *testing.T) {
		var bs []byte
		bs = bier.BierSetBit(bs, 23) // byte index 2
		if len(bs) < 3 {
			t.Errorf("slice should be at least 3 bytes, got %d", len(bs))
		}
		if !bier.BierGetBit(bs, 23) {
			t.Error("bit 23 should be set")
		}
		// Preceding bytes should be zero
		if bs[0] != 0 || bs[1] != 0 {
			t.Error("lower bytes should be zero after setting bit 23 only")
		}
	})

	t.Run("SetBit boundary — bit 7 is MSB of first byte", func(t *testing.T) {
		var bs []byte
		bs = bier.BierSetBit(bs, 7)
		if bs[0] != 0x80 {
			t.Errorf("expected 0x80, got %02x", bs[0])
		}
	})

	t.Run("SetBit boundary — bit 8 is LSB of second byte", func(t *testing.T) {
		var bs []byte
		bs = bier.BierSetBit(bs, 8)
		if len(bs) < 2 || bs[1] != 0x01 {
			t.Errorf("expected second byte 0x01, got %v", bs)
		}
	})

	t.Run("ClearBit out-of-bounds is a no-op", func(t *testing.T) {
		bs := []byte{0xFF}
		bier.BierClearBit(bs, 100) // should not panic
		if bs[0] != 0xFF {
			t.Error("ClearBit out-of-bounds should not modify the slice")
		}
	})

	t.Run("ClearBit on nil is a no-op", func(t *testing.T) {
		bier.BierClearBit(nil, 0) // must not panic
	})

	t.Run("bier.BierAnd with different length slices", func(t *testing.T) {
		a := []byte{0xFF, 0xFF, 0xFF} // 3 bytes
		b := []byte{0x0F, 0xF0}       // 2 bytes — shorter
		res := bier.BierAnd(a, b)
		if len(res) != 3 {
			t.Errorf("result length should be max(3,2)=3, got %d", len(res))
		}
		if res[0] != 0x0F || res[1] != 0xF0 || res[2] != 0x00 {
			t.Errorf("unexpected result %v", res)
		}
	})

	t.Run("bier.BierAnd both nil/empty returns empty", func(t *testing.T) {
		res := bier.BierAnd(nil, nil)
		if len(res) != 0 {
			t.Errorf("AND of two nils should be empty")
		}
	})

	t.Run("bier.BierAndNot shorter mask", func(t *testing.T) {
		a := []byte{0xFF, 0xFF} // 2 bytes
		b := []byte{0x0F}       // 1 byte — shorter
		res := bier.BierAndNot(a, b)
		// Only first byte gets bits cleared
		if res[0] != 0xF0 {
			t.Errorf("byte 0: expected 0xF0, got %02x", res[0])
		}
		if res[1] != 0xFF {
			t.Errorf("byte 1: expected 0xFF, got %02x", res[1])
		}
	})

	t.Run("bier.BierIsZero on nil is true", func(t *testing.T) {
		if !bier.BierIsZero(nil) {
			t.Error("nil bitstring should be zero")
		}
	})

	t.Run("bier.BierIsZero on empty slice is true", func(t *testing.T) {
		if !bier.BierIsZero([]byte{}) {
			t.Error("empty bitstring should be zero")
		}
	})

	t.Run("bier.BierClone of nil returns nil", func(t *testing.T) {
		if bier.BierClone(nil) != nil {
			t.Error("clone of nil should be nil")
		}
	})

	t.Run("bier.BierClone of empty slice returns empty (not nil)", func(t *testing.T) {
		c := bier.BierClone([]byte{})
		if c == nil {
			t.Error("clone of empty slice should be non-nil")
		}
		if len(c) != 0 {
			t.Error("clone of empty slice should be length 0")
		}
	})

	t.Run("Large bit positions (multi-byte)", func(t *testing.T) {
		var bs []byte
		positions := []int{0, 63, 64, 127, 255}
		for _, pos := range positions {
			bs = bier.BierSetBit(bs, pos)
		}
		for _, pos := range positions {
			if !bier.BierGetBit(bs, pos) {
				t.Errorf("bit %d should be set", pos)
			}
		}
		// Adjacent bits should be clear
		if bier.BierGetBit(bs, 1) {
			t.Error("bit 1 should not be set")
		}
		if bier.BierGetBit(bs, 62) {
			t.Error("bit 62 should not be set")
		}
	})
}

// --- bier.IsBierEnabled / bier.CfgBierIndex ---

func TestBierEnabledConfig(t *testing.T) {
	t.Run("disabled when BierIndex is -1 (default)", func(t *testing.T) {
		restore := setBierIndex(-1)
		defer restore()
		if bier.IsBierEnabled() {
			t.Error("BIER should be disabled when BierIndex=-1")
		}
		if bier.CfgBierIndex() != -1 {
			t.Error("bier.CfgBierIndex should return -1")
		}
	})

	t.Run("enabled when BierIndex is 0", func(t *testing.T) {
		restore := setBierIndex(0)
		defer restore()
		if !bier.IsBierEnabled() {
			t.Error("BIER should be enabled when BierIndex=0")
		}
	})

	t.Run("enabled for large index", func(t *testing.T) {
		restore := setBierIndex(255)
		defer restore()
		if !bier.IsBierEnabled() {
			t.Error("BIER should be enabled when BierIndex=255")
		}
	})
}

// --- BIFT edge cases ---

func TestBiftEdgeCases(t *testing.T) {
	t.Run("GetNeighborEntries on empty BIFT", func(t *testing.T) {
		b := &bier.BiftState{}
		neighbors := b.GetNeighborEntries()
		if len(neighbors) != 0 {
			t.Errorf("empty BIFT should have 0 neighbors, got %d", len(neighbors))
		}
	})

	t.Run("GetNeighborEntries skips entries with no next hop", func(t *testing.T) {
		b := &bier.BiftState{}
		r := enc.Name{enc.NewGenericComponent("r")}
		b.RegisterRouter(r, 0)
		// No UpdateNextHop call — NextHop is 0

		neighbors := b.GetNeighborEntries()
		if len(neighbors) != 0 {
			t.Errorf("router with zero NextHop should not appear in neighbors, got %d", len(neighbors))
		}
	})

	t.Run("GetNeighborEntries skips entries with nil F-BM", func(t *testing.T) {
		b := &bier.BiftState{}
		r := enc.Name{enc.NewGenericComponent("r")}
		b.RegisterRouter(r, 1)
		b.UpdateNextHop(1, 99)
		// RebuildFbm NOT called — Fbm is nil

		neighbors := b.GetNeighborEntries()
		if len(neighbors) != 0 {
			t.Errorf("router with nil Fbm should not appear in neighbors, got %d", len(neighbors))
		}
	})

	t.Run("GetNeighborEntries aggregates all bits for same face", func(t *testing.T) {
		b := &bier.BiftState{}
		r0 := enc.Name{enc.NewGenericComponent("r0")}
		r1 := enc.Name{enc.NewGenericComponent("r1")}
		r9 := enc.Name{enc.NewGenericComponent("r9")}

		b.RegisterRouter(r0, 0)
		b.RegisterRouter(r1, 1)
		b.RegisterRouter(r9, 9)

		b.UpdateNextHop(0, 77)
		b.UpdateNextHop(1, 77)
		b.UpdateNextHop(9, 77)
		b.RebuildFbm()

		neighbors := b.GetNeighborEntries()
		if len(neighbors) != 1 {
			t.Fatalf("expected 1 neighbor entry, got %d", len(neighbors))
		}

		fbm := neighbors[0].Fbm
		if !bier.BierGetBit(fbm, 0) || !bier.BierGetBit(fbm, 1) || !bier.BierGetBit(fbm, 9) {
			t.Fatalf("expected aggregated F-BM to contain bits 0, 1, and 9; got %08b %08b", fbm[0], fbm[1])
		}
	})

	t.Run("RebuildFbm on empty BIFT does not panic", func(t *testing.T) {
		b := &bier.BiftState{}
		b.RebuildFbm() // must not panic
	})

	t.Run("BuildBierBitString with empty egress list returns nil", func(t *testing.T) {
		b := &bier.BiftState{}
		bs := b.BuildBierBitString(nil)
		if bs != nil {
			t.Errorf("empty egress list should return nil, got %v", bs)
		}
	})

	t.Run("BuildBierBitString with all unknown routers returns nil", func(t *testing.T) {
		b := &bier.BiftState{}
		unknown := enc.Name{enc.NewGenericComponent("unknown")}
		bs := b.BuildBierBitString([]enc.Name{unknown})
		if bs != nil {
			t.Errorf("all-unknown egress routers should return nil, got %v", bs)
		}
	})

	t.Run("RegisterRouter overwrites existing BFR-ID", func(t *testing.T) {
		b := &bier.BiftState{}
		r := enc.Name{enc.NewGenericComponent("router")}
		b.RegisterRouter(r, 3)
		b.RegisterRouter(r, 7) // re-register same name, different bit

		id, ok := b.GetRouterBfrId(r)
		if !ok {
			t.Fatal("router should exist after re-registration")
		}
		if id != 7 {
			t.Errorf("after re-registration BFR-ID should be 7, got %d", id)
		}
	})

	t.Run("UpdateNextHop on non-existent BFR-ID is a no-op", func(t *testing.T) {
		b := &bier.BiftState{}
		b.UpdateNextHop(99, 100) // must not panic
	})

	t.Run("RebuildFbm groups multiple BFR-IDs per face", func(t *testing.T) {
		b := &bier.BiftState{}
		for i := 0; i < 8; i++ {
			name := enc.Name{enc.NewGenericComponent("r" + string(rune('0'+i)))}
			b.RegisterRouter(name, i)
			b.UpdateNextHop(i, 555) // all share one face
		}
		b.RebuildFbm()

		neighbors := b.GetNeighborEntries()
		if len(neighbors) != 1 {
			t.Fatalf("expected 1 neighbor (face 555), got %d", len(neighbors))
		}
		fbm := neighbors[0].Fbm
		for i := 0; i < 8; i++ {
			if !bier.BierGetBit(fbm, i) {
				t.Errorf("F-BM for face 555 should have bit %d set", i)
			}
		}
	})

	t.Run("Multiple calls to BuildFromFib do not corrupt state", func(t *testing.T) {
		// Calling BuildFromFib requires FibStrategyTable to be initialized.
		// Use table.Initialize() to set it up with the default config.
		table.Initialize()

		b := &bier.BiftState{}
		r := enc.Name{enc.NewGenericComponent("r")}
		b.RegisterRouter(r, 0)
		b.BuildFromFib() // FIB empty → no next hops resolved, no panic
		b.BuildFromFib() // second call also safe
	})
}

// --- Concurrent access ---

func TestBiftConcurrency(t *testing.T) {
	b := &bier.BiftState{}
	var wg sync.WaitGroup
	const goroutines = 20

	// Concurrent RegisterRouter
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			name := enc.Name{enc.NewGenericComponent("cr" + string(rune('A'+i%26)))}
			b.RegisterRouter(name, i%64)
		}(i)
	}
	wg.Wait()

	// Concurrent GetRouterBfrId while UpdateNextHop runs
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			b.UpdateNextHop(i%64, uint64(100+i))
		}(i)
		go func(i int) {
			defer wg.Done()
			name := enc.Name{enc.NewGenericComponent("cr" + string(rune('A'+i%26)))}
			b.GetRouterBfrId(name)
		}(i)
	}
	wg.Wait()

	// Concurrent RebuildFbm + GetNeighborEntries
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			b.RebuildFbm()
		}()
		go func() {
			defer wg.Done()
			b.GetNeighborEntries()
		}()
	}
	wg.Wait()
}

func TestBiftBuildBierBitStringMixed(t *testing.T) {
	b := &bier.BiftState{}
	known := enc.Name{enc.NewGenericComponent("known")}
	unknown := enc.Name{enc.NewGenericComponent("unknown")}

	b.RegisterRouter(known, 3)
	egressRouters := []enc.Name{known, unknown}
	bs := b.BuildBierBitString(egressRouters)

	// Only bit 3 should be set (unknown skipped)
	if !bier.BierGetBit(bs, 3) {
		t.Error("bit 3 should be set for known router")
	}
	if bier.BierGetBit(bs, 0) || bier.BierGetBit(bs, 1) || bier.BierGetBit(bs, 2) {
		t.Error("only bit 3 should be set")
	}
}

func TestBierAndNotDoesNotModifyInputs(t *testing.T) {
	a := []byte{0xFF, 0xFF}
	b := []byte{0x0F, 0xF0}
	aCopy := bier.BierClone(a)
	bCopy := bier.BierClone(b)

	bier.BierAndNot(a, b)

	for i := range a {
		if a[i] != aCopy[i] {
			t.Errorf("bier.BierAndNot mutated a at byte %d", i)
		}
	}
	for i := range b {
		if b[i] != bCopy[i] {
			t.Errorf("bier.BierAndNot mutated b at byte %d", i)
		}
	}
}

func TestBierAndDoesNotModifyInputs(t *testing.T) {
	a := []byte{0xAA, 0xBB}
	b := []byte{0xCC, 0xDD}
	aCopy := bier.BierClone(a)
	bCopy := bier.BierClone(b)

	bier.BierAnd(a, b)

	for i := range a {
		if a[i] != aCopy[i] {
			t.Errorf("bier.BierAnd mutated a at byte %d", i)
		}
	}
	for i := range b {
		if b[i] != bCopy[i] {
			t.Errorf("bier.BierAnd mutated b at byte %d", i)
		}
	}
}
