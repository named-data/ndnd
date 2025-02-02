package gen_basic_test

import (
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/encoding/tests/gen_basic"
	"github.com/named-data/ndnd/std/utils"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

func TestFakeMetaInfo(t *testing.T) {
	tu.SetT(t)

	f := gen_basic.FakeMetaInfo{
		Number: 1,
		Time:   2 * time.Second,
		Binary: []byte{3, 4, 5},
	}
	buf := f.Bytes()
	require.Equal(t,
		[]byte{
			0x18, 0x01, 0x01,
			0x19, 0x02, 0x07, 0xd0,
			0x1a, 0x03, 0x03, 0x04, 0x05,
		},
		buf)

	f2 := tu.NoErr(gen_basic.ParseFakeMetaInfo(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)

	buf2 := []byte{
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
	}
	tu.Err(gen_basic.ParseFakeMetaInfo(enc.NewFastBufReader(buf2), false))

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x08, 0x03, 0x04, 0x05,
	}
	tu.Err(gen_basic.ParseFakeMetaInfo(enc.NewFastBufReader(buf2), false))

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
		0x30, 0x01, 0x00,
	}
	f2 = tu.NoErr(gen_basic.ParseFakeMetaInfo(enc.NewFastBufReader(buf2), false))
	require.Equal(t, f, *f2)

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
		0x31, 0x01, 0x00,
	}
	f2 = tu.NoErr(gen_basic.ParseFakeMetaInfo(enc.NewFastBufReader(buf2), true))
	require.Equal(t, f, *f2)

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
		0x31, 0x01, 0x00,
	}
	tu.Err(gen_basic.ParseFakeMetaInfo(enc.NewFastBufReader(buf2), false))
}

func TestOptField(t *testing.T) {
	tu.SetT(t)

	f := gen_basic.OptField{
		Number: utils.IdPtr[uint64](1),
		Time:   utils.IdPtr(2 * time.Second),
		Binary: []byte{3, 4, 5},
		Bool:   true,
	}
	buf := f.Bytes()
	require.Equal(t,
		[]byte{
			0x18, 0x01, 0x01,
			0x19, 0x02, 0x07, 0xd0,
			0x1a, 0x03, 0x03, 0x04, 0x05,
			0x30, 0x00,
		},
		buf)
	f2 := tu.NoErr(gen_basic.ParseOptField(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)

	f = gen_basic.OptField{
		Number: nil,
		Time:   nil,
		Binary: nil,
		Bool:   false,
	}
	buf = f.Bytes()
	require.Equal(t,
		[]byte{},
		buf)
	f2 = tu.NoErr(gen_basic.ParseOptField(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)

	f = gen_basic.OptField{
		Number: utils.IdPtr[uint64](0),
		Time:   utils.IdPtr(0 * time.Second),
		Binary: []byte{},
	}
	buf = f.Bytes()
	require.Equal(t,
		[]byte{
			0x18, 0x01, 0x00,
			0x19, 0x01, 0x00,
			0x1a, 0x00,
		},
		buf)
	f2 = tu.NoErr(gen_basic.ParseOptField(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)
}

func TestWireName(t *testing.T) {
	tu.SetT(t)

	f := gen_basic.WireNameField{
		Wire: enc.Wire{
			[]byte{1, 2, 3},
			[]byte{4, 5, 6},
		},
		Name: tu.NoErr(enc.NameFromStr("/A/B/C")),
	}
	buf := f.Bytes()
	require.Equal(t,
		[]byte{
			0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x02, 0x09, 0x08, 0x01, 'A', 0x08, 0x01, 'B', 0x08, 0x01, 'C',
		},
		buf)
	f2 := tu.NoErr(gen_basic.ParseWireNameField(enc.NewFastBufReader(buf), false))
	require.True(t, f.Name.Equal(f2.Name))
	require.Equal(t, f.Wire.Join(), f2.Wire.Join())

	f2 = tu.NoErr(gen_basic.ParseWireNameField(enc.NewFastBufReader([]byte{}), false))
	require.Equal(t, enc.Name(nil), f2.Name)
	require.Equal(t, enc.Wire(nil), f2.Wire)

	f2 = tu.NoErr(gen_basic.ParseWireNameField(enc.NewFastBufReader(
		[]byte{
			0x01, 0x00, 0x02, 0x00,
		}), false))
	require.Equal(t, enc.Name{}, f2.Name)
	require.Equal(t, []byte{}, f2.Wire.Join())
}

func TestMarkers(t *testing.T) {
	tu.SetT(t)

	f := gen_basic.Markers{
		Wire: enc.Wire{
			[]byte{1, 2, 3},
			[]byte{4, 5, 6},
		},
		Name: tu.NoErr(enc.NameFromStr("/A/B/C")),
	}
	buf := f.Encode(1)
	require.Equal(t,
		[]byte{
			0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x02, 0x09, 0x08, 0x01, 'A', 0x08, 0x01, 'B', 0x08, 0x01, 'C',
		},
		buf)
	f2 := gen_basic.ParseMarkers(buf, 2)
	require.True(t, f.Name.Equal(f2.Name))
	require.Equal(t, f.Wire.Join(), f2.Wire.Join())
}

func TestNoCopy(t *testing.T) {
	tu.SetT(t)

	f := gen_basic.NoCopyStruct{
		Wire1: enc.Wire{
			[]byte{1, 2, 3},
			[]byte{4, 5, 6},
		},
		Number: 1,
		Wire2: enc.Wire{
			[]byte{7, 8, 9},
			[]byte{10, 11, 12},
		},
	}
	wire := f.Encode()
	require.Equal(t, []byte{0x01, 0x06}, []byte(wire[0]))
	require.Equal(t, []byte{0x01, 0x02, 0x03}, []byte(wire[1]))
	require.Equal(t, []byte{0x04, 0x05, 0x06}, []byte(wire[2]))
	require.Equal(t, []byte{0x02, 0x01, 0x01, 0x03, 0x06}, []byte(wire[3]))
	require.Equal(t, []byte{0x07, 0x08, 0x09}, []byte(wire[4]))
	require.Equal(t, []byte{0x0a, 0x0b, 0x0c}, []byte(wire[5]))
	for i := 6; i < len(wire); i++ {
		require.Equal(t, enc.Buffer(nil), wire[i])
	}
	f2 := tu.NoErr(gen_basic.ParseNoCopyStruct(enc.NewFastReader(wire), true))
	require.Equal(t, f.Wire1.Join(), f2.Wire1.Join())
	require.Equal(t, f.Number, f2.Number)
	require.Equal(t, f.Wire2.Join(), f2.Wire2.Join())
}

func TestStrField(t *testing.T) {
	tu.SetT(t)

	f := gen_basic.StrField{
		Str1: "hello",
		Str2: utils.IdPtr("world"),
	}
	buf := f.Bytes()
	require.Equal(t, []byte{0x01, 0x05, 'h', 'e', 'l', 'l', 'o', 0x02, 0x05, 'w', 'o', 'r', 'l', 'd'}, buf)
	f2 := tu.NoErr(gen_basic.ParseStrField(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)

	f = gen_basic.StrField{
		Str1: "",
		Str2: nil,
	}
	buf = f.Bytes()
	require.Equal(t, []byte{0x01, 0x00}, buf)
	f2 = tu.NoErr(gen_basic.ParseStrField(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)

	buf = []byte{}
	tu.Err(gen_basic.ParseStrField(enc.NewFastBufReader(buf), false))
}

func TestFixedUintField(t *testing.T) {
	tu.SetT(t)

	f := gen_basic.FixedUintField{
		Byte: 1,
		U32:  utils.IdPtr[uint32](2),
		U64:  utils.IdPtr[uint64](3),
	}
	buf := f.Bytes()
	require.Equal(t, []byte{
		0x01, 0x01, 0x01,
		0x02, 0x04, 0x00, 0x00, 0x00, 0x02,
		0x03, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	}, buf)
	f2 := tu.NoErr(gen_basic.ParseFixedUintField(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)

	f = gen_basic.FixedUintField{
		Byte: 0,
		U32:  nil,
		U64:  nil,
	}
	buf = f.Bytes()
	require.Equal(t, []byte{
		0x01, 0x01, 0x00,
	}, buf)
	f2 = tu.NoErr(gen_basic.ParseFixedUintField(enc.NewFastBufReader(buf), false))
	require.Equal(t, f, *f2)

	buf = []byte{}
	tu.Err(gen_basic.ParseFixedUintField(enc.NewFastBufReader(buf), false))
}
