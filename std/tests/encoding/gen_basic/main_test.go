package gen_basic_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"github.com/zjkmxy/go-ndn/tests/encoding/gen_basic"
)

func TestFakeMetaInfo(t *testing.T) {
	utils.SetTestingT(t)

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

	f2 := utils.WithoutErr(gen_basic.ParseFakeMetaInfo(enc.NewBufferReader(buf), false))
	require.Equal(t, f, *f2)

	buf2 := []byte{
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
	}
	utils.WithErr(gen_basic.ParseFakeMetaInfo(enc.NewBufferReader(buf2), false))

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x08, 0x03, 0x04, 0x05,
	}
	utils.WithErr(gen_basic.ParseFakeMetaInfo(enc.NewBufferReader(buf2), false))

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
		0x30, 0x01, 0x00,
	}
	f2 = utils.WithoutErr(gen_basic.ParseFakeMetaInfo(enc.NewBufferReader(buf2), false))
	require.Equal(t, f, *f2)

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
		0x31, 0x01, 0x00,
	}
	f2 = utils.WithoutErr(gen_basic.ParseFakeMetaInfo(enc.NewBufferReader(buf2), true))
	require.Equal(t, f, *f2)

	buf2 = []byte{
		0x18, 0x01, 0x01,
		0x19, 0x02, 0x07, 0xd0,
		0x1a, 0x03, 0x03, 0x04, 0x05,
		0x31, 0x01, 0x00,
	}
	utils.WithErr(gen_basic.ParseFakeMetaInfo(enc.NewBufferReader(buf2), false))
}

func TestOptField(t *testing.T) {
	utils.SetTestingT(t)

	f := gen_basic.OptField{
		Number: utils.ConstPtr[uint64](1),
		Time:   utils.ConstPtr(2 * time.Second),
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
	f2 := utils.WithoutErr(gen_basic.ParseOptField(enc.NewBufferReader(buf), false))
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
	f2 = utils.WithoutErr(gen_basic.ParseOptField(enc.NewBufferReader(buf), false))
	require.Equal(t, f, *f2)

	f = gen_basic.OptField{
		Number: utils.ConstPtr[uint64](0),
		Time:   utils.ConstPtr(0 * time.Second),
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
	f2 = utils.WithoutErr(gen_basic.ParseOptField(enc.NewBufferReader(buf), false))
	require.Equal(t, f, *f2)
}

func TestWireName(t *testing.T) {
	utils.SetTestingT(t)

	f := gen_basic.WireNameField{
		Wire: enc.Wire{
			[]byte{1, 2, 3},
			[]byte{4, 5, 6},
		},
		Name: utils.WithoutErr(enc.NameFromStr("/A/B/C")),
	}
	buf := f.Bytes()
	require.Equal(t,
		[]byte{
			0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x02, 0x09, 0x08, 0x01, 'A', 0x08, 0x01, 'B', 0x08, 0x01, 'C',
		},
		buf)
	f2 := utils.WithoutErr(gen_basic.ParseWireNameField(enc.NewBufferReader(buf), false))
	require.True(t, f.Name.Equal(f2.Name))
	require.Equal(t, f.Wire.Join(), f2.Wire.Join())

	f2 = utils.WithoutErr(gen_basic.ParseWireNameField(enc.NewBufferReader([]byte{}), false))
	require.Equal(t, enc.Name(nil), f2.Name)
	require.Equal(t, enc.Wire(nil), f2.Wire)

	f2 = utils.WithoutErr(gen_basic.ParseWireNameField(enc.NewBufferReader(
		[]byte{
			0x01, 0x00, 0x02, 0x00,
		}), false))
	require.Equal(t, enc.Name{}, f2.Name)
	require.Equal(t, []byte{}, f2.Wire.Join())
}
