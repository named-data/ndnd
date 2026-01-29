package encoding

import (
	"fmt"
	"io"
)

type BufferReader struct {
	buf Buffer
	pos int
}

// (AI GENERATED DESCRIPTION): Copies data from the BufferReader's internal buffer into the supplied byte slice, advancing the read position and returning io.EOF when the buffer is fully consumed.
func (r *BufferReader) Read(b []byte) (int, error) {
	if r.pos >= len(r.buf) && len(b) > 0 {
		return 0, io.EOF
	}
	n := copy(b, r.buf[r.pos:])
	r.pos += n
	return n, nil
}

// (AI GENERATED DESCRIPTION): Returns the next byte from the internal buffer, or io.EOF if the end of the buffer has been reached.
func (r *BufferReader) ReadByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	ret := r.buf[r.pos]
	r.pos++
	return ret, nil
}

// (AI GENERATED DESCRIPTION): Decrements the reader's position by one byte so the next read returns the same byte again, returning an error if the position is already at the start of the buffer.
func (r *BufferReader) UnreadByte() error {
	if r.pos == 0 {
		return fmt.Errorf("encoding.BufferReader.UnreadByte: negative position")
	}
	r.pos--
	return nil
}

// (AI GENERATED DESCRIPTION): Adjusts the reader’s internal position within its buffer according to the given offset and whence, enforcing bounds and returning an error for invalid parameters.
func (r *BufferReader) Seek(offset int64, whence int) (int64, error) {
	var newPos int
	switch whence {
	case io.SeekStart:
		newPos = int(offset)
	case io.SeekCurrent:
		newPos = r.pos + int(offset)
	case io.SeekEnd:
		newPos = len(r.buf) - int(offset)
	default:
		return 0, fmt.Errorf("encoding.BufferReader.Seek: invalid whence")
	}
	if newPos < 0 {
		return 0, fmt.Errorf("encoding.BufferReader.Seek: negative position")
	}
	if newPos > len(r.buf) {
		return 0, fmt.Errorf("encoding.BufferReader.Seek: position out of range")
	}
	r.pos = newPos
	return int64(r.pos), nil
}

// (AI GENERATED DESCRIPTION): Advances the reader’s current position by n bytes, erroring if the resulting index would be negative or beyond the buffer’s length.
func (r *BufferReader) Skip(n int) error {
	newPos := r.pos + n
	if newPos < 0 {
		return fmt.Errorf("encoding.BufferReader.Skip: negative position")
	}
	if newPos > len(r.buf) {
		return fmt.Errorf("encoding.BufferReader.Skip: position out of range")
	}
	r.pos = newPos
	return nil
}

// (AI GENERATED DESCRIPTION): Reads `l` bytes from the reader’s internal buffer, returns them as a `Wire`, advances the read position, and signals `EOF` or `UnexpectedEOF` if the buffer does not contain enough data.
func (r *BufferReader) ReadWire(l int) (Wire, error) {
	if r.pos >= len(r.buf) && l > 0 {
		return nil, io.EOF
	}
	if r.pos+l > len(r.buf) {
		return nil, io.ErrUnexpectedEOF
	}
	p := r.pos
	r.pos += l
	return Wire{r.buf[p:r.pos]}, nil
}

// (AI GENERATED DESCRIPTION): ReadBuf reads l bytes from the internal buffer, advancing the read position, and returns an io.ErrUnexpectedEOF error if the buffer does not contain enough data.
func (r *BufferReader) ReadBuf(l int) (Buffer, error) {
	if r.pos+l > len(r.buf) {
		return nil, io.ErrUnexpectedEOF
	}
	p := r.pos
	r.pos += l
	return r.buf[p:r.pos], nil
}

// (AI GENERATED DESCRIPTION): Returns the current read position of the BufferReader.
func (r *BufferReader) Pos() int {
	return r.pos
}

// (AI GENERATED DESCRIPTION): Returns the number of bytes currently stored in the BufferReader’s internal buffer.
func (r *BufferReader) Length() int {
	return len(r.buf)
}

// (AI GENERATED DESCRIPTION): Returns a Wire slice of the buffer between `start` (inclusive) and `end` (exclusive), or nil if the indices are out of bounds.
func (r *BufferReader) Range(start, end int) Wire {
	if start < 0 || end > len(r.buf) || start > end {
		return nil
	}
	return Wire{r.buf[start:end]}
}

// (AI GENERATED DESCRIPTION): Creates a new `ParseReader` that reads the next `l` bytes of the buffer (advancing the current position) or returns an empty reader if the requested length is out of bounds.
func (r *BufferReader) Delegate(l int) ParseReader {
	if l < 0 || r.pos+l > len(r.buf) {
		return NewBufferReader([]byte{})
	}
	subBuf := r.buf[r.pos : r.pos+l]
	r.pos += l
	return NewBufferReader(subBuf)
}

// (AI GENERATED DESCRIPTION): Initializes a BufferReader with the supplied Buffer, setting the starting position to zero.
func NewBufferReader(buf Buffer) *BufferReader {
	return &BufferReader{
		buf: buf,
		pos: 0,
	}
}

// WireReader is used for reading from a Wire.
// It is used when parsing a fragmented packet.
type WireReader struct {
	wire  Wire
	seg   int
	pos   int
	accSz []int
}

// (AI GENERATED DESCRIPTION): Advances to the next wire segment when the current read position has reached the end of the current segment, returning true if another segment remains to be processed.
func (r *WireReader) nextSeg() bool {
	if r.seg < len(r.wire) && r.pos >= len(r.wire[r.seg]) {
		r.seg++
		r.pos = 0
	}
	return r.seg < len(r.wire)
}

// (AI GENERATED DESCRIPTION): Reads bytes from the wire buffer into the supplied slice, advancing the read position and returning `io.EOF` once all segments have been consumed.
func (r *WireReader) Read(b []byte) (int, error) {
	if !r.nextSeg() && len(b) > 0 {
		return 0, io.EOF
	}
	n := copy(b, r.wire[r.seg][r.pos:])
	r.pos += n
	return n, nil
}

// (AI GENERATED DESCRIPTION): Reads the next byte from the wire buffer, advancing the internal position and returning `io.EOF` when the buffer is exhausted.
func (r *WireReader) ReadByte() (byte, error) {
	if !r.nextSeg() {
		return 0, io.EOF
	}
	ret := r.wire[r.seg][r.pos]
	r.pos++
	return ret, nil
}

// (AI GENERATED DESCRIPTION): Rewinds the WireReader by one byte, moving the read position back by a single byte across segment boundaries and returning an error if already at the very start.
func (r *WireReader) UnreadByte() error {
	if r.pos == 0 {
		if r.seg == 0 {
			return fmt.Errorf("encoding.WireReader.UnreadByte: negative position")
		}
		r.seg--
		r.pos = len(r.wire[r.seg])
	}
	r.pos--
	return nil
}

// (AI GENERATED DESCRIPTION): Reads `l` bytes from the WireReader’s segmented buffer, returning a `Wire` slice that spans the needed segments and updates the reader’s position, or an error if the buffer ends before `l` bytes are available.
func (r *WireReader) ReadWire(l int) (Wire, error) {
	if !r.nextSeg() && l > 0 {
		return nil, io.EOF
	}
	ret := make(Wire, 0, len(r.wire)-r.seg)
	for l > 0 {
		if r.seg >= len(r.wire) {
			return nil, io.ErrUnexpectedEOF
		}
		if r.pos+l > len(r.wire[r.seg]) {
			ret = append(ret, r.wire[r.seg][r.pos:])
			l -= len(r.wire[r.seg]) - r.pos
			r.seg++
			r.pos = 0
		} else {
			ret = append(ret, r.wire[r.seg][r.pos:r.pos+l])
			r.pos += l
			l = 0
		}
	}
	return ret, nil
}

// (AI GENERATED DESCRIPTION): Reads up to `l` bytes from a segmented wire buffer, returning a contiguous `Buffer` that may span multiple segments, or `io.ErrUnexpectedEOF` if the requested data exceeds the available data.
func (r *WireReader) ReadBuf(l int) (Buffer, error) {
	if !r.nextSeg() && l > 0 {
		return nil, io.ErrUnexpectedEOF
	}
	if r.pos+l <= len(r.wire[r.seg]) {
		p := r.pos
		r.pos += l
		return r.wire[r.seg][p:r.pos], nil
	} else {
		ret := make(Buffer, l)
		cur := 0
		for l > 0 {
			if r.seg >= len(r.wire) {
				return nil, io.ErrUnexpectedEOF
			}
			if r.pos+l > len(r.wire[r.seg]) {
				copy(ret[cur:], r.wire[r.seg][r.pos:])
				l -= len(r.wire[r.seg]) - r.pos
				cur += len(r.wire[r.seg]) - r.pos
				r.seg++
				r.pos = 0
			} else {
				copy(ret[cur:], r.wire[r.seg][r.pos:r.pos+l])
				r.pos += l
				cur -= l
				l = 0
			}
		}
		return ret, nil
	}
}

// (AI GENERATED DESCRIPTION): Returns the current absolute read position in the wire buffer, including any accumulated segment offsets.
func (r *WireReader) Pos() int {
	return r.pos + r.accSz[r.seg]
}

// (AI GENERATED DESCRIPTION): Returns the cumulative byte length of the data parsed so far by this WireReader.
func (r *WireReader) Length() int {
	return r.accSz[len(r.wire)]
}

// (AI GENERATED DESCRIPTION): Extracts and returns a Wire comprising the bytes from the original WireReader between the specified start and end offsets, preserving segment boundaries, or nil if the range is out of bounds.
func (r *WireReader) Range(start, end int) Wire {
	if start < 0 || end > r.accSz[len(r.wire)] || start > end {
		return nil
	}
	var startSeg, startPos, endSeg, endPos int
	for i := 0; i < len(r.wire); i++ {
		if r.accSz[i] <= start && r.accSz[i+1] > start {
			startSeg = i
			startPos = start - r.accSz[i]
		}
		if r.accSz[i] < end && r.accSz[i+1] >= end {
			endSeg = i
			endPos = end - r.accSz[i]
		}
	}
	if startSeg == endSeg {
		return Wire{r.wire[startSeg][startPos:endPos]}
	} else {
		ret := make(Wire, endSeg-startSeg+1)
		ret[0] = r.wire[startSeg][startPos:]
		for i := startSeg + 1; i < endSeg; i++ {
			ret[i] = r.wire[i]
		}
		ret[endSeg-startSeg] = r.wire[endSeg][:endPos]
		return ret
	}
}

// (AI GENERATED DESCRIPTION): Skips forward `n` bytes in the wire buffer, advancing across segment boundaries, and returns an error if `n` is negative or the skip would run past the end of the data.
func (r *WireReader) Skip(n int) error {
	if n < 0 {
		return fmt.Errorf("encoding.WireReader.Skip: backword skipping is not allowed")
	}
	r.pos += n
	for r.pos > len(r.wire[r.seg]) {
		r.pos -= len(r.wire[r.seg])
		r.seg++
		if r.seg >= len(r.wire) {
			return io.EOF
		}
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Delegates the next l bytes from the current WireReader to a new ParseReader, advancing the original reader’s position and returning either a buffer or a new WireReader that spans exactly that byte range.
func (r *WireReader) Delegate(l int) ParseReader {
	if l < 0 || r.seg >= len(r.wire) {
		return NewBufferReader([]byte{})
	}
	if r.pos+l <= len(r.wire[r.seg]) {
		// Return a buffer reader
		startPos := r.pos
		r.pos += l
		return NewBufferReader(r.wire[r.seg][startPos:r.pos])
	}
	// Return a wire reader
	startSeg := r.seg
	startPos := r.pos
	r.pos += l
	for r.pos > len(r.wire[r.seg]) {
		r.pos -= len(r.wire[r.seg])
		r.seg++
		if r.seg >= len(r.wire) {
			return NewBufferReader([]byte{})
		}
	}
	if r.pos == len(r.wire[r.seg]) {
		return &WireReader{
			wire:  r.wire[0 : r.seg+1],
			seg:   startSeg,
			pos:   startPos,
			accSz: r.accSz[0 : r.seg+2],
		}
	} else {
		newWire := Wire{}
		newWire = append(newWire, r.wire[startSeg:r.seg+1]...)
		newWire[0] = newWire[0][startPos:]
		newWire[len(newWire)-1] = newWire[len(newWire)-1][:r.pos]
		return NewWireReader(newWire)
	}
}

// (AI GENERATED DESCRIPTION): Creates a new WireReader for the supplied wire, initializing segment and position to zero and precomputing cumulative segment sizes for efficient traversal.
func NewWireReader(w Wire) *WireReader {
	accSz := make([]int, len(w)+1)
	accSz[0] = 0
	for i := 0; i < len(w); i++ {
		accSz[i+1] = accSz[i] + len(w[i])
	}
	return &WireReader{
		wire:  w,
		seg:   0,
		pos:   0,
		accSz: accSz,
	}
}
