package encoding

import (
	"io"
)

type FastReader struct {
	wire  Wire
	apos  int // absolute position from start of wire
	rpos  int // relative position within segment
	seg   int // segment index
	start int // first allowed position (absolute)
	end   int // last allowed position (absolute)
}

func NewFastReader(wire Wire) FastReader {
	end := 0
	for _, seg := range wire {
		end += len(seg)
	}
	return FastReader{wire: wire, end: end}
}

func NewFastBufReader(buf Buffer) FastReader {
	return NewFastReader(Wire{buf})
}

func (r *FastReader) IsValid() bool {
	return r.apos < r.end
}

func (r *FastReader) Pos() int {
	return r.apos - r.start
}

func (r *FastReader) Length() int {
	return r.end - r.start
}

func (r *FastReader) ReadByte() (byte, error) {
	if !r.IsValid() {
		return 0, ErrBufferOverflow
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

func (r *FastReader) ReadFull(cpy []byte) (int, error) {
	cpypos := 0
	for cpypos < len(cpy) {
		if !r.IsValid() {
			return cpypos, ErrBufferOverflow
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

func (r *FastReader) Skip(n int) error {
	_, err := r.SkipGetSegCount(n)
	return err
}

// _skip skips the next n bytes.
// used as utility for ReadWire to get the number of segments to read.
func (r *FastReader) SkipGetSegCount(n int) (int, error) {
	segcount := 0
	left := n
	for left > 0 {
		segcount++
		if !r.IsValid() {
			return segcount, ErrBufferOverflow
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

func (r *FastReader) ReadWire(size int) (Wire, error) {
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
func (r *FastReader) readSeg(size int) []byte {
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

func (r *FastReader) Delegate(size int) FastReader {
	if size > r.end-r.apos {
		return FastReader{} // invalid
	}
	ret := *r
	ret.start = ret.apos
	ret.end = ret.apos + size
	r.Skip(size)
	return ret
}

func (r *FastReader) CopyN(w io.Writer, size int64) (int, error) {
	written := 0
	for written < int(size) {
		if !r.IsValid() {
			return written, ErrBufferOverflow
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

func (r *FastReader) ReadBuf(size int) ([]byte, error) {
	if size > r.end-r.apos {
		return nil, ErrBufferOverflow
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

func (r *FastReader) Range(start, end int) Wire {
	rcopy := *r
	rcopy.Skip(start)
	w, err := rcopy.ReadWire(end - start)
	if err != nil {
		return Wire{}
	}
	return w
}
