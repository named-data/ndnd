package encoding_test

import (
	"io"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests the core functionality of WireReader and BufferReader by reading, skipping, ranging, and delegating over a predefined wire and its joined byte buffer, ensuring both readers produce identical results and correctly handle EOF conditions.
func TestBasic(t *testing.T) {
	tu.SetT(t)

	wire := enc.Wire{
		[]byte{0x01, 0x02, 0x03},
		[]byte{0x04},
		[]byte{0x05, 0x06},
		[]byte{0x07, 0x08, 0x09, 0x0a},
		[]byte{0x0b, 0x0c, 0x0d},
		[]byte{0x0e, 0x0f},
	}
	buf := wire.Join()
	wr := enc.NewWireReader(wire)
	br := enc.NewBufferReader(buf)

	require.Equal(t, len(buf), wr.Length())
	require.Equal(t, len(buf), br.Length())
	require.Equal(t, 0, wr.Pos())
	require.Equal(t, 0, br.Pos())

	testRead := func(l int) {
		b1 := make([]byte, l)
		b2 := make([]byte, l)
		n1 := tu.NoErr(io.ReadFull(wr, b1))
		n2 := tu.NoErr(io.ReadFull(br, b2))
		require.Equal(t, n1, n2)
		require.Equal(t, b1, b2)
		require.Equal(t, wr.Pos(), br.Pos())
	}

	testRead(1)
	testRead(1)
	testRead(3)
	testRead(1)
	testRead(3)
	testRead(4)
	testRead(1)

	_, err := io.ReadFull(wr, []byte{0x00, 0x00})
	require.Equal(t, io.ErrUnexpectedEOF, err)
	_, err = io.ReadFull(br, []byte{0x00, 0x00})
	require.Equal(t, io.ErrUnexpectedEOF, err)
	_, err = io.ReadFull(wr, []byte{0x00, 0x00})
	require.Equal(t, io.EOF, err)
	_, err = io.ReadFull(br, []byte{0x00, 0x00})
	require.Equal(t, io.EOF, err)

	testRange := func(start, end int) {
		w1 := wr.Range(start, end)
		w2 := br.Range(start, end)
		require.Equal(t, w1.Join(), w2.Join())
	}

	testRange(0, 0)
	testRange(0, 1)
	testRange(1, 3)
	testRange(1, 4)
	testRange(1, 5)
	testRange(1, 6)
	testRange(7, 100)

	testSkip := func(l int) {
		wr.Skip(l)
		br.Skip(l)
	}

	wr = enc.NewWireReader(wire)
	br = enc.NewBufferReader(buf)
	testSkip(1)
	testRead(1)
	testSkip(3)
	testRead(1)
	testSkip(3)
	testRead(4)
	testSkip(1)

	wr = enc.NewWireReader(wire)
	br = enc.NewBufferReader(buf)
	testRead(1)
	testSkip(1)
	testRead(3)
	testSkip(1)
	testRead(3)
	testSkip(4)
	testRead(1)

	testReadWire := func(l int) {
		w1 := tu.NoErr(wr.ReadWire(l))
		w2 := tu.NoErr(br.ReadWire(l))
		require.Equal(t, w1.Join(), w2.Join())
	}
	wr = enc.NewWireReader(wire)
	br = enc.NewBufferReader(buf)
	testReadWire(1)
	testReadWire(1)
	testReadWire(3)
	testReadWire(1)
	testReadWire(3)
	testReadWire(4)
	testReadWire(1)

	testDelegate := func(l int) {
		r1 := wr.Delegate(l)
		r2 := br.Delegate(l)
		b1 := tu.NoErr(io.ReadAll(r1))
		b2 := tu.NoErr(io.ReadAll(r2))
		require.Equal(t, b1, b2)
	}
	wr = enc.NewWireReader(wire)
	br = enc.NewBufferReader(buf)
	testDelegate(1)
	testDelegate(1)
	testDelegate(3)
	testDelegate(1)
	testDelegate(3)
	testDelegate(4)
	testDelegate(1)
}
