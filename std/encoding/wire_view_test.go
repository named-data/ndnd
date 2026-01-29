package encoding_test

import (
	"bufio"
	"bytes"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

var FrTestWire = enc.Wire{
	[]byte{0x01, 0x02, 0x03},
	[]byte{0x04},
	[]byte{0x05, 0x06},
	[]byte{0x07, 0x08, 0x09, 0x0a},
	[]byte{0x0b, 0x0c, 0x0d},
	[]byte{0x0e, 0x0f},
}

// (AI GENERATED DESCRIPTION): TestWireViewReadByte verifies that a WireView correctly reads each byte sequentially from the given wire data, updates its read position accordingly, and reports EOF once all bytes have been consumed.
func TestWireViewReadByte(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)
	require.False(t, r.IsEOF())
	require.Equal(t, 0, r.Pos())
	require.Equal(t, 15, r.Length())

	for i := 1; i <= 15; i++ {
		require.Equal(t, uint8(i), tu.NoErr(r.ReadByte()))
		require.Equal(t, i, r.Pos())
	}
	require.True(t, r.IsEOF())
}

// (AI GENERATED DESCRIPTION): Tests that a WireView reads sequential bytes correctly, sets EOF after the final read, and returns a buffer‑overflow error when attempting to read beyond the end of the underlying wire data.
func TestWireViewReadFull(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)

	// Move 1 byte ahead
	require.Equal(t, uint8(1), tu.NoErr(r.ReadByte()))

	// Read 6 bytes
	buf := make([]byte, 6)
	n, err := r.ReadFull(buf)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte{0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, buf)
	require.False(t, r.IsEOF())

	// Read 8 bytes
	buf = make([]byte, 8)
	n, err = r.ReadFull(buf)
	require.NoError(t, err)
	require.Equal(t, 8, n)
	require.Equal(t, []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, buf)
	require.True(t, r.IsEOF())

	// Read 1 byte
	buf = make([]byte, 1)
	n, err = r.ReadFull(buf)
	require.Equal(t, 0, n)
	require.Equal(t, enc.ErrBufferOverflow, err)
}

// (AI GENERATED DESCRIPTION): Tests the WireView Skip method, confirming it advances the read position correctly, detects end‑of‑file, and returns an error when a skip would exceed the buffer.
func TestWireViewSkip(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)

	// Skip 1 byte
	require.NoError(t, r.Skip(1))
	require.Equal(t, 1, r.Pos())

	// Read 2 bytes
	buf := make([]byte, 2)
	tu.NoErr(r.ReadFull(buf))
	require.Equal(t, []byte{0x02, 0x03}, buf)

	// Skip 8 bytes
	require.NoError(t, r.Skip(8))
	require.Equal(t, 11, r.Pos())

	// Read 1 byte
	tu.NoErr(r.ReadByte())
	require.Equal(t, 12, r.Pos())

	r1 := r // copy r

	// Skip 3 bytes
	require.NoError(t, r.Skip(3))
	require.Equal(t, 15, r.Pos())
	require.True(t, r.IsEOF())
	require.Error(t, r.Skip(1))

	// Skip 4 bytes on copy
	require.Equal(t, 12, r1.Pos())
	require.Error(t, r1.Skip(4))
}

// (AI GENERATED DESCRIPTION): Tests the WireView’s ReadWire, Skip, and EOF logic by sequentially reading and segmenting a predefined wire, ensuring correct position updates, segment boundaries, and proper overflow errors.
func TestWireViewReadWire(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)

	// Read 3 bytes
	wire, err := r.ReadWire(2)
	require.NoError(t, err)
	require.Equal(t, enc.Wire{[]byte{0x01, 0x02}}, wire)
	require.Equal(t, 2, r.Pos())

	// Read 6 bytes
	wire, err = r.ReadWire(6)
	require.NoError(t, err)
	require.Equal(t, enc.Wire{[]byte{0x03}, []byte{0x04}, []byte{0x05, 0x06}, []byte{0x07, 0x08}}, wire)
	require.Equal(t, 8, r.Pos())

	// Skip 1 byte
	require.NoError(t, r.Skip(1))

	r1 := r // copy r

	// Read 6 bytes
	wire, err = r.ReadWire(6)
	require.NoError(t, err)
	require.Equal(t, enc.Wire{[]byte{0x0a}, []byte{0x0b, 0x0c, 0x0d}, []byte{0x0e, 0x0f}}, wire)
	require.Equal(t, 15, r.Pos())
	require.True(t, r.IsEOF())

	// Read 1 byte
	_, err = r.ReadWire(1)
	require.Equal(t, enc.ErrBufferOverflow, err)

	// Read 7 bytes on copy
	require.Equal(t, 9, r1.Pos())
	_, err = r1.ReadWire(7)
	require.Equal(t, enc.ErrBufferOverflow, err)
}

// (AI GENERATED DESCRIPTION): **Tests the `WireView.Delegate` method, verifying that subviews are correctly created, positions and lengths are tracked, EOF semantics are respected, and bounds are enforced during reads and skips.**
func TestWireViewDelegate(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)

	// Delegate 5 bytes
	r1 := r.Delegate(5)
	require.Equal(t, 5, r.Pos())
	require.Equal(t, 0, r1.Pos())
	require.Equal(t, 15, r.Length())
	require.Equal(t, 5, r1.Length())
	require.False(t, r1.IsEOF())

	// Read from delegate
	buf := make([]byte, 5)
	tu.NoErr(r1.ReadFull(buf))
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, buf)
	require.Equal(t, 5, r1.Pos())
	require.True(t, r1.IsEOF())
	require.Error(t, r1.Skip(1))

	// Delegate 8 bytes
	r2 := r.Delegate(8)
	require.Equal(t, 5+8, r.Pos())
	require.Equal(t, 0, r2.Pos())
	require.Equal(t, 15, r.Length())
	require.Equal(t, 8, r2.Length())
	require.False(t, r2.IsEOF())

	// copy r2
	r2c1, r2c2, r2c3 := r2, r2, r2

	// Read from delegate
	buf = tu.NoErr(r2.ReadBuf(3))
	require.Equal(t, []byte{0x06, 0x07, 0x08}, buf)
	require.Equal(t, 3, r2.Pos())
	require.False(t, r2.IsEOF())

	// Skip inside delegate
	require.NoError(t, r2.Skip(1))
	require.Equal(t, 4, r2.Pos())
	require.False(t, r2.IsEOF())

	// Read from delegate after skip
	buf = tu.NoErr(r2.ReadBuf(4))
	require.Equal(t, []byte{0x0a, 0x0b, 0x0c, 0x0d}, buf)
	require.Equal(t, 8, r2.Pos())
	require.True(t, r2.IsEOF())

	// Skip outside of bounds
	require.Error(t, r2.Skip(1))

	// Read from delegate outside of bounds
	tu.Err(r2c1.ReadBuf(9))
	tu.Err(r2c2.ReadFull(make([]byte, 9)))
	require.Error(t, r2c3.Skip(9))

	rcpy := r // copy r

	// Delegate 2 bytes
	r3 := r.Delegate(2)
	require.Equal(t, 5+8+2, r.Pos())
	require.Equal(t, 0, r3.Pos())
	require.True(t, r.IsEOF())
	require.False(t, r3.IsEOF())

	// Delegate outside of bounds
	r4 := rcpy.Delegate(11)
	require.Equal(t, 5+8, rcpy.Pos()) // rcpy is not affected
	require.False(t, rcpy.IsEOF())
	require.True(t, r4.IsEOF())
	require.Error(t, r4.Skip(1))
}

// (AI GENERATED DESCRIPTION): Copies up to N bytes from a WireView into an io.Writer, returning the number of bytes actually written and an ErrBufferOverflow if the WireView contained fewer bytes than requested.
func TestWireViewCopyN(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)
	var b bytes.Buffer
	w := bufio.NewWriter(&b)

	// copy 10 bytes
	n, err := r.CopyN(w, 10)
	require.NoError(t, err)
	require.Equal(t, 10, n)
	require.NoError(t, w.Flush())
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}, b.Bytes())

	r1 := r // copy r

	// copy 5 bytes
	b.Reset()
	n, err = r.CopyN(w, 5)
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.NoError(t, w.Flush())
	require.Equal(t, []byte{0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, b.Bytes())
	require.True(t, r.IsEOF())

	// copy 6 bytes
	b.Reset()
	require.True(t, !r1.IsEOF())
	n, err = r1.CopyN(w, 6)
	require.Equal(t, 5, n)
	require.Equal(t, enc.ErrBufferOverflow, err)
}

// (AI GENERATED DESCRIPTION): Tests reading and skipping bytes from a WireView, verifying correct position updates, EOF detection, and error handling for buffer overflows.
func TestWireViewReadBuf(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)

	// Read 3 bytes
	buf, err := r.ReadBuf(2)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02}, buf)
	require.Equal(t, 2, r.Pos())

	// Read 6 bytes
	buf, err = r.ReadBuf(6)
	require.NoError(t, err)
	require.Equal(t, []byte{0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, buf)
	require.Equal(t, 8, r.Pos())

	// Skip 1 byte
	require.NoError(t, r.Skip(1))

	r1 := r // copy r

	// Read 6 bytes
	buf, err = r.ReadBuf(6)
	require.NoError(t, err)
	require.Equal(t, []byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, buf)
	require.Equal(t, 15, r.Pos())
	require.True(t, r.IsEOF())
	buf, err = r.ReadBuf(1)
	require.Equal(t, enc.ErrBufferOverflow, err)
	require.Nil(t, buf)

	// Read 7 bytes on copy
	require.Equal(t, 9, r1.Pos())
	buf, err = r1.ReadBuf(7)
	require.Equal(t, enc.ErrBufferOverflow, err)
	require.Nil(t, buf)
}

// (AI GENERATED DESCRIPTION): Returns a sub‑view of the underlying wire data from the given start offset up to, but not including, the end offset, yielding an empty view when the range is empty or invalid.
func TestWireViewRange(t *testing.T) {
	tu.SetT(t)

	r := enc.NewWireView(FrTestWire)

	// Range 0-2
	wire := r.Range(0, 2)
	require.Equal(t, enc.Wire{[]byte{0x01, 0x02}}, wire)

	// Range 3-8
	wire = r.Range(3, 8)
	require.Equal(t, enc.Wire{[]byte{0x04}, []byte{0x05, 0x06}, []byte{0x07, 0x08}}, wire)

	// Range 8-15
	wire = r.Range(8, 15)
	require.Equal(t, enc.Wire{[]byte{0x09, 0x0a}, []byte{0x0b, 0x0c, 0x0d}, []byte{0x0e, 0x0f}}, wire)

	// Range 15-15
	wire = r.Range(15, 15)
	require.Equal(t, enc.Wire{}, wire)

	// Range 14-16
	wire = r.Range(14, 16)
	require.Equal(t, enc.Wire{}, wire)

	// Range 16-15
	wire = r.Range(16, 15)
	require.Equal(t, enc.Wire{}, wire)
}
