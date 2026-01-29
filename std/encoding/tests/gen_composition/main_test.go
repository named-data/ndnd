package gen_composition_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	def "github.com/named-data/ndnd/std/encoding/tests/gen_composition"
	"github.com/named-data/ndnd/std/types/optional"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests that an IntArray can be correctly serialized to a byte slice and parsed back, ensuring proper handling of both non‑empty and empty word slices.
func TestIntArray(t *testing.T) {
	tu.SetT(t)

	f := def.IntArray{
		Words: []uint64{1, 2, 3},
	}
	buf := f.Bytes()
	require.Equal(t, []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03}, buf)
	f2 := tu.NoErr(def.ParseIntArray(enc.NewBufferView(buf), false))
	require.Equal(t, f, *f2)

	f = def.IntArray{
		Words: []uint64{},
	}
	buf = f.Bytes()
	require.Equal(t, []byte{}, buf)
	f2 = tu.NoErr(def.ParseIntArray(enc.NewBufferView(buf), false))
	require.Equal(t, 0, len(f2.Words))
}

// (AI GENERATED DESCRIPTION): **TestNameArray** verifies that a `NameArray` is correctly serialized to a byte buffer via `Bytes()` and can be round‑tripped back to the original structure with `ParseNameArray`.
func TestNameArray(t *testing.T) {
	tu.SetT(t)

	f := def.NameArray{
		Names: []enc.Name{
			tu.NoErr(enc.NameFromStr("/A/B")),
			tu.NoErr(enc.NameFromStr("/C")),
		},
	}
	buf := f.Bytes()
	require.Equal(t, []byte{
		0x07, 0x06, 0x08, 0x01, 'A', 0x08, 0x01, 'B',
		0x07, 0x03, 0x08, 0x01, 'C'}, buf)
	f2 := tu.NoErr(def.ParseNameArray(enc.NewBufferView(buf), false))
	require.Equal(t, f, *f2)
}

// (AI GENERATED DESCRIPTION): Serializes a Nested structure containing an optional Inner value to bytes and parses it back, ensuring both populated and nil cases round‑trip correctly.
func TestNested(t *testing.T) {
	tu.SetT(t)

	f := def.Nested{
		Val: &def.Inner{
			Num: 255,
		},
	}
	buf := f.Bytes()
	require.Equal(t, []byte{0x02, 0x03, 0x01, 0x01, 0xff}, buf)
	f2 := tu.NoErr(def.ParseNested(enc.NewBufferView(buf), false))
	require.Equal(t, f.Val.Num, f2.Val.Num)

	f = def.Nested{
		Val: nil,
	}
	buf = f.Bytes()
	require.Equal(t, 0, len(buf))
	f2 = tu.NoErr(def.ParseNested(enc.NewBufferView(buf), false))
	require.True(t, f2.Val == nil)
}

// (AI GENERATED DESCRIPTION): Tests that a NestedSeq struct is correctly serialized to bytes and parsed back, verifying the byte format for non‑empty and empty value lists.
func TestNestedSeq(t *testing.T) {
	tu.SetT(t)

	f := def.NestedSeq{
		Vals: []*def.Inner{
			{Num: 255},
			{Num: 256},
		},
	}
	buf := f.Bytes()
	require.Equal(t, []byte{
		0x03, 0x03, 0x01, 0x01, 0xff,
		0x03, 0x04, 0x01, 0x02, 0x01, 0x00,
	}, buf)
	f2 := tu.NoErr(def.ParseNestedSeq(enc.NewBufferView(buf), false))
	require.Equal(t, 2, len(f2.Vals))
	require.Equal(t, uint64(255), f2.Vals[0].Num)
	require.Equal(t, uint64(256), f2.Vals[1].Num)

	f = def.NestedSeq{
		Vals: nil,
	}
	buf = f.Bytes()
	require.Equal(t, 0, len(buf))
	f2 = tu.NoErr(def.ParseNestedSeq(enc.NewBufferView(buf), false))
	require.Equal(t, 0, len(f2.Vals))
}

// (AI GENERATED DESCRIPTION): Tests that `NestedWire` structs are correctly encoded to and decoded from binary wire format, covering nested inner wires, optional fields, and handling of empty or nil values.
func TestNestedWire(t *testing.T) {
	tu.SetT(t)

	f := def.NestedWire{
		W1: &def.InnerWire1{
			Wire1: enc.Wire{
				[]byte{1, 2, 3},
				[]byte{4, 5, 6},
			},
			Num: optional.Some[uint64](255),
		},
		N: 13,
		W2: &def.InnerWire2{
			Wire2: enc.Wire{
				[]byte{7, 8, 9},
				[]byte{10, 11, 12},
			},
		},
	}
	wire := f.Encode()
	require.GreaterOrEqual(t, len(wire), 6)
	buf := wire.Join()
	require.Equal(t, []byte{
		0x04, 0x0b,
		0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02, 0x01, 0xff,
		0x05, 0x01, 0x0d,
		0x06, 0x08,
		0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	}, buf)
	f2 := tu.NoErr(def.ParseNestedWire(enc.NewWireView(wire), false))
	require.Equal(t, f.W1.Wire1.Join(), f2.W1.Wire1.Join())
	require.Equal(t, f.W1.Num, f2.W1.Num)
	require.Equal(t, f.N, f2.N)
	require.Equal(t, f.W2.Wire2.Join(), f2.W2.Wire2.Join())

	f = def.NestedWire{
		W1: &def.InnerWire1{
			Wire1: enc.Wire{},
			Num:   optional.None[uint64](),
		},
		N: 0,
		W2: &def.InnerWire2{
			Wire2: enc.Wire{},
		},
	}
	buf = f.Bytes()
	require.Equal(t, []byte{
		0x04, 0x02,
		0x01, 0x00,
		0x05, 0x01, 0,
		0x06, 0x02,
		0x03, 0x00,
	}, buf)
	f2 = tu.NoErr(def.ParseNestedWire(enc.NewBufferView(buf), false))
	require.Equal(t, 0, len(f2.W1.Wire1.Join()))
	require.False(t, f2.W1.Wire1 == nil)
	require.Equal(t, 0, len(f2.W2.Wire2.Join()))
	require.False(t, f2.W2.Wire2 == nil)

	f = def.NestedWire{
		W1: &def.InnerWire1{
			Wire1: nil,
			Num:   optional.None[uint64](),
		},
		N: 0,
		W2: &def.InnerWire2{
			Wire2: nil,
		},
	}
	buf = f.Bytes()
	require.Equal(t, []byte{0x04, 0x00, 0x05, 0x01, 0, 0x06, 0x00}, buf)
	f2 = tu.NoErr(def.ParseNestedWire(enc.NewBufferView(buf), false))
	require.Equal(t, enc.Wire(nil), f2.W1.Wire1)
	require.Equal(t, enc.Wire(nil), f2.W2.Wire2)

	f = def.NestedWire{
		W1: nil,
		N:  0,
		W2: nil,
	}
	buf = f.Bytes()
	require.Equal(t, []byte{0x05, 0x01, 0}, buf)
	f2 = tu.NoErr(def.ParseNestedWire(enc.NewBufferView(buf), false))
	require.True(t, f2.W1 == nil)
	require.True(t, f2.W2 == nil)
}
