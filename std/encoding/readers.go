package encoding

import (
	"errors"
	"io"
	"sync"
)

var bufferReaderPool = sync.Pool{
	New: func() any { return &BufferReader{} },
}

type BufferReader struct {
	buf Buffer
	pos int
}

func (r *BufferReader) Read(b []byte) (int, error) {
	if r.pos >= len(r.buf) && len(b) > 0 {
		return 0, io.EOF
	}
	n := copy(b, r.buf[r.pos:])
	r.pos += n
	return n, nil
}

func (r *BufferReader) ReadByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	ret := r.buf[r.pos]
	r.pos++
	return ret, nil
}

func (r *BufferReader) UnreadByte() error {
	if r.pos == 0 {
		return errors.New("encoding.BufferReader.UnreadByte: negative position")
	}
	r.pos--
	return nil
}

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
		return 0, errors.New("encoding.BufferReader.Seek: invalid whence")
	}
	if newPos < 0 {
		return 0, errors.New("encoding.BufferReader.Seek: negative position")
	}
	if newPos > len(r.buf) {
		return 0, errors.New("encoding.BufferReader.Seek: position out of range")
	}
	r.pos = newPos
	return int64(r.pos), nil
}

func (r *BufferReader) Skip(n int) error {
	newPos := r.pos + n
	if newPos < 0 {
		return errors.New("encoding.BufferReader.Skip: negative position")
	}
	if newPos > len(r.buf) {
		return errors.New("encoding.BufferReader.Skip: position out of range")
	}
	r.pos = newPos
	return nil
}

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

func (r *BufferReader) ReadBuf(l int) (Buffer, error) {
	if r.pos+l > len(r.buf) {
		return nil, io.ErrUnexpectedEOF
	}
	p := r.pos
	r.pos += l
	return r.buf[p:r.pos], nil
}

func (r *BufferReader) Pos() int {
	return r.pos
}

func (r *BufferReader) Length() int {
	return len(r.buf)
}

func (r *BufferReader) Range(start, end int) Wire {
	if start < 0 || end > len(r.buf) || start > end {
		return nil
	}
	return Wire{r.buf[start:end]}
}

func (r *BufferReader) Delegate(l int) ParseReader {
	if l < 0 || r.pos+l > len(r.buf) {
		return NewBufferReader([]byte{})
	}
	subBuf := r.buf[r.pos : r.pos+l]
	r.pos += l
	return NewBufferReader(subBuf)
}

func (r *BufferReader) Free() {
	r.buf = nil // gc
	bufferReaderPool.Put(r)
}

func NewBufferReader(buf Buffer) *BufferReader {
	r := bufferReaderPool.Get().(*BufferReader)
	r.buf = buf
	r.pos = 0
	return r
}

// WireReader is used for reading from a Wire.
// It is used when parsing a fragmented packet.
type WireReader struct {
	wire  Wire
	seg   int
	pos   int
	accSz []int
}

func (r *WireReader) nextSeg() bool {
	if r.seg < len(r.wire) && r.pos >= len(r.wire[r.seg]) {
		r.seg++
		r.pos = 0
	}
	return r.seg < len(r.wire)
}

func (r *WireReader) Read(b []byte) (int, error) {
	if !r.nextSeg() && len(b) > 0 {
		return 0, io.EOF
	}
	n := copy(b, r.wire[r.seg][r.pos:])
	r.pos += n
	return n, nil
}

func (r *WireReader) ReadByte() (byte, error) {
	if !r.nextSeg() {
		return 0, io.EOF
	}
	ret := r.wire[r.seg][r.pos]
	r.pos++
	return ret, nil
}

func (r *WireReader) UnreadByte() error {
	if r.pos == 0 {
		if r.seg == 0 {
			return errors.New("encoding.WireReader.UnreadByte: negative position")
		}
		r.seg--
		r.pos = len(r.wire[r.seg])
	}
	r.pos--
	return nil
}

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

func (r *WireReader) Pos() int {
	return r.pos + r.accSz[r.seg]
}

func (r *WireReader) Length() int {
	return r.accSz[len(r.wire)]
}

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

func (r *WireReader) Skip(n int) error {
	if n < 0 {
		return errors.New("encoding.WireReader.Skip: backword skipping is not allowed")
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

func (r *WireReader) Free() {
	// no pool needed
}

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
