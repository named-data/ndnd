package encoding

import (
	"io"
)

// WireView is a parsing view of a Wire.
// It lives entirely on the stack and fits in a cache line.
type WireView struct {
	wire  Wire
	apos  int // absolute position from start of wire
	rpos  int // relative position within segment
	seg   int // segment index
	start int // first allowed position (absolute)
	end   int // last allowed position (absolute)
}

// (AI GENERATED DESCRIPTION): Creates a WireView from the given wire segments, precomputing the total byte length of the data.
func NewWireView(wire Wire) WireView {
	end := 0
	for _, seg := range wire {
		end += len(seg)
	}
	return WireView{wire: wire, end: end}
}

// (AI GENERATED DESCRIPTION): Creates a `WireView` that wraps the supplied `Buffer` so it can be treated as a wire representation.
func NewBufferView(buf Buffer) WireView {
	return NewWireView(Wire{buf})
}

// (AI GENERATED DESCRIPTION): Returns true when the current read position has reached or passed the end of the view, indicating no more data to read.
func (r *WireView) IsEOF() bool {
	return r.apos >= r.end
}

// (AI GENERATED DESCRIPTION): Returns the current offset within the WireView relative to its start index.
func (r *WireView) Pos() int {
	return r.apos - r.start
}

// (AI GENERATED DESCRIPTION): Returns the number of bytes represented by the WireView.
func (r *WireView) Length() int {
	return r.end - r.start
}

// (AI GENERATED DESCRIPTION): Retrieves the next byte from the wire view, advancing the read position across segment boundaries, and returns an EOF error if the view has been exhausted.
func (r *WireView) ReadByte() (byte, error) {
	if r.IsEOF() {
		return 0, r._eof()
	}
	b := r.wire[r.seg][r.rpos]
	r.apos++
	r.rpos++
	if r.rpos == len(r.wire[r.seg]) {
		r.rpos = 0
		r.seg++
	}
	return b, nil
}

// (AI GENERATED DESCRIPTION): Copies all remaining bytes from the underlying wire view into the supplied buffer, returning an error if the buffer is larger than the data available.
func (r *WireView) ReadFull(cpy []byte) (int, error) {
	cpypos := 0
	for cpypos < len(cpy) {
		if r.IsEOF() {
			return cpypos, r._overflow()
		}
		n := copy(cpy[cpypos:], r.wire[r.seg][r.rpos:])
		cpypos += n
		r.apos += n
		r.rpos += n
		if r.rpos == len(r.wire[r.seg]) {
			r.rpos = 0
			r.seg++
		}
	}
	return cpypos, nil
}

// (AI GENERATED DESCRIPTION): Skips forward n bytes in the current wire view, discarding the skipped data and returning any error that occurs.
func (r *WireView) Skip(n int) error {
	_, err := r.SkipGetSegCount(n)
	return err
}

// _skip skips the next n bytes.
// used as utility for ReadWire to get the number of segments to read.
func (r *WireView) SkipGetSegCount(n int) (int, error) {
	segcount := 0
	left := n
	for left > 0 {
		segcount++
		if r.IsEOF() {
			return segcount, r._overflow()
		}
		segleft := len(r.wire[r.seg]) - r.rpos
		if left < segleft {
			r.apos += left
			r.rpos += left
			return segcount, nil
		} else {
			left -= segleft
			r.apos += segleft
			r.rpos = 0
			r.seg++
		}
	}
	return segcount, nil
}

// (AI GENERATED DESCRIPTION): **ReadWire** reads the specified number of bytes from the WireView, performing bounds checking, and returns them as a Wire (a slice of byte‑segment slices).
func (r *WireView) ReadWire(size int) (Wire, error) {
	r_sz := *r // copy
	w_size, err := r_sz.SkipGetSegCount(size)
	if err != nil {
		return nil, err
	}

	// bounds checking is already done
	ret := make(Wire, w_size)
	for i := 0; i < w_size; i++ {
		ret[i] = r.readSeg(size)
		size -= len(ret[i])
	}

	return ret, nil
}

// reads upto size bytes from the current segment, without copying.
func (r *WireView) readSeg(size int) []byte {
	segleft := len(r.wire[r.seg]) - r.rpos
	if size < segleft {
		ret := r.wire[r.seg][r.rpos : r.rpos+size]
		r.apos += size
		r.rpos += size
		return ret
	} else {
		ret := r.wire[r.seg][r.rpos:]
		r.apos += segleft
		r.rpos = 0
		r.seg++
		return ret
	}
}

// (AI GENERATED DESCRIPTION): Creates a sub‑view of the specified size from the current read position, advancing the original view past that region, and returns an empty view if the requested size exceeds the remaining bytes.
func (r *WireView) Delegate(size int) WireView {
	if size > r.end-r.apos {
		return WireView{} // invalid
	}
	ret := *r
	ret.start = ret.apos
	ret.end = ret.apos + size
	r.Skip(size)
	return ret
}

// (AI GENERATED DESCRIPTION): Copies up to `size` bytes from the `WireView` into the supplied `io.Writer`, stopping on EOF or overflow and returning the number of bytes actually written along with any error.
func (r *WireView) CopyN(w io.Writer, size int) (int, error) {
	written := 0
	for written < size {
		if r.IsEOF() {
			return written, r._overflow()
		}
		seg := r.readSeg(int(size) - written)
		written += len(seg)
		n, err := w.Write(seg)
		if n != len(seg) {
			return written, io.ErrShortWrite
		}
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// (AI GENERATED DESCRIPTION): Reads up to a requested number of bytes from the current position of the wire view, automatically handling segment boundaries and returning an error if the read would exceed the wire size or hit the end of the data.
func (r *WireView) ReadBuf(size int) ([]byte, error) {
	if size > r.end-r.apos {
		return nil, r._overflow()
	}
	if size == 0 {
		return []byte{}, nil
	}
	if r.IsEOF() {
		return []byte{}, r._eof()
	}

	// skip allocation if the entire buffer is in the current segment
	if size <= len(r.wire[r.seg])-r.rpos {
		ret := r.wire[r.seg][r.rpos : r.rpos+size]
		r.apos += size
		r.rpos += size
		if r.rpos == len(r.wire[r.seg]) {
			r.rpos = 0
			r.seg++
		}
		return ret, nil
	}

	ret := make([]byte, size)
	written := 0
	for written < size {
		seg := r.readSeg(size - written)
		copy(ret[written:], seg)
		written += len(seg)
	}
	return ret, nil
}

// (AI GENERATED DESCRIPTION): Returns a sub‑Wire representing the bytes from the given start offset to the end offset within the current WireView, or an empty Wire on error.
func (r *WireView) Range(start, end int) Wire {
	rcopy := WireView{wire: r.wire, end: r.end}
	rcopy.Skip(r.start + start)
	w, err := rcopy.ReadWire(end - start)
	if err != nil {
		return Wire{}
	}
	return w
}

// Debug prints the remaining bytes in the buffer.
func (r WireView) Debug() []byte {
	b, _ := r.ReadBuf(r.end - r.apos)
	return b
}

// (AI GENERATED DESCRIPTION): Signals that the wire view has been fully consumed by returning the standard `io.EOF` error.
func (r *WireView) _eof() error {
	return io.EOF
}

// (AI GENERATED DESCRIPTION): Returns an `ErrBufferOverflow` error, signaling that the underlying wire buffer has exceeded its capacity.
func (r *WireView) _overflow() error {
	return ErrBufferOverflow
}
