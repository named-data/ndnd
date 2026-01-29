package gen_map_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	def "github.com/named-data/ndnd/std/encoding/tests/gen_map"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests that a `StringMap` can be correctly serialized to a byte buffer and parsed back, ensuring round‑trip fidelity and proper handling of empty parameter maps.
func TestStringMap(t *testing.T) {
	tu.SetT(t)

	f := def.StringMap{
		Params: map[string][]byte{
			"a":  []byte("a"),
			"b":  []byte("bb"),
			"cc": []byte("cccc"),
		},
	}
	buf := f.Bytes()
	// Note: orders are not preserved, so we shouldn't check the result
	// require.Equal(t, []byte{0x85, 0x1, 0x61, 0x87, 0x1, 0x61,
	// 	0x85, 0x1, 0x62, 0x87, 0x2, 0x62, 0x62,
	// 	0x85, 0x2, 0x63, 0x63, 0x87, 0x4, 0x63, 0x63, 0x63, 0x63}, buf)
	f2 := tu.NoErr(def.ParseStringMap(enc.NewBufferView(buf), false))
	require.Equal(t, f, *f2)

	f = def.StringMap{
		Params: map[string][]byte{},
	}
	buf = f.Bytes()
	require.Equal(t, []byte{}, buf)
	f2 = tu.NoErr(def.ParseStringMap(enc.NewBufferView(buf), false))
	require.Equal(t, 0, len(f2.Params))
}

// (AI GENERATED DESCRIPTION): Tests the serialization and deserialization of an `IntStructMap`, verifying that a map of integer keys to `Inner` structs round‑trips correctly and that an empty map serializes to an empty byte slice.
func TestIntStructMap(t *testing.T) {
	tu.SetT(t)

	f := def.IntStructMap{
		Params: map[uint64]*def.Inner{
			1: {1},
			2: {2},
			3: {3},
		},
	}
	buf := f.Bytes()
	// Note: orders are not preserved, so we shouldn't check the result
	// require.Equal(t, []byte{0x85, 0x1, 0x2, 0x87, 0x3, 0x1, 0x1, 0x2,
	// 	0x85, 0x1, 0x3, 0x87, 0x3, 0x1, 0x1, 0x3,
	// 	0x85, 0x1, 0x1, 0x87, 0x3, 0x1, 0x1, 0x1}, buf)
	f2 := tu.NoErr(def.ParseIntStructMap(enc.NewBufferView(buf), false))
	require.Equal(t, f, *f2)

	f = def.IntStructMap{
		Params: map[uint64]*def.Inner{},
	}
	buf = f.Bytes()
	require.Equal(t, []byte{}, buf)
	f2 = tu.NoErr(def.ParseIntStructMap(enc.NewBufferView(buf), false))
	require.Equal(t, 0, len(f2.Params))
}
