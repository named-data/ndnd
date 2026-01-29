package encoding

import (
	"encoding/binary"
	"io"
)

// TLNum is a TLV Type or Length number
type TLNum uint64

// Nat is a TLV natural number
type Nat uint64

// (AI GENERATED DESCRIPTION): Computes the number of bytes needed to encode a TLNum value using the NDN variable‑length TLV format.
func (v TLNum) EncodingLength() int {
	switch x := uint64(v); {
	case x <= 0xfc:
		return 1
	case x <= 0xffff:
		return 3
	case x <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

// (AI GENERATED DESCRIPTION): Encodes a TLNum value into the provided buffer using a variable-length integer format, returning the number of bytes written.
func (v TLNum) EncodeInto(buf Buffer) int {
	switch x := uint64(v); {
	case x <= 0xfc:
		buf[0] = byte(x)
		return 1
	case x <= 0xffff:
		buf[0] = 0xfd
		binary.BigEndian.PutUint16(buf[1:], uint16(x))
		return 3
	case x <= 0xffffffff:
		buf[0] = 0xfe
		binary.BigEndian.PutUint32(buf[1:], uint32(x))
		return 5
	default:
		buf[0] = 0xff
		binary.BigEndian.PutUint64(buf[1:], uint64(x))
		return 9
	}
}

// ParseTLNum parses a TLNum from a buffer.
// It is supposed to be used internally, so panic on index out of bounds.
func ParseTLNum(buf Buffer) (val TLNum, pos int) {
	switch x := buf[0]; {
	case x <= 0xfc:
		val = TLNum(x)
		pos = 1
	case x == 0xfd:
		val = TLNum(binary.BigEndian.Uint16(buf[1:3]))
		pos = 3
	case x == 0xfe:
		val = TLNum(binary.BigEndian.Uint32(buf[1:5]))
		pos = 5
	case x == 0xff:
		val = TLNum(binary.BigEndian.Uint64(buf[1:9]))
		pos = 9
	}
	return
}

// ReadTLNum reads a TLNum from a wire view
func (r *WireView) ReadTLNum() (val TLNum, err error) {
	var x byte
	if x, err = r.ReadByte(); err != nil {
		return
	}
	l := 1
	switch {
	case x <= 0xfc:
		val = TLNum(x)
		return
	case x == 0xfd:
		l = 2
	case x == 0xfe:
		l = 4
	case x == 0xff:
		l = 8
	}
	val = 0
	for i := 0; i < l; i++ {
		if x, err = r.ReadByte(); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return
		}
		val = TLNum(val<<8) | TLNum(x)
	}
	return
}

// (AI GENERATED DESCRIPTION): Returns the minimal number of bytes (1, 2, 4, or 8) needed to represent the Nat value in a variable‑length numeric encoding.
func (v Nat) EncodingLength() int {
	switch x := uint64(v); {
	case x <= 0xff:
		return 1
	case x <= 0xffff:
		return 2
	case x <= 0xffffffff:
		return 4
	default:
		return 8
	}
}

// (AI GENERATED DESCRIPTION): Encodes a Nat value into the provided buffer using the fewest big‑endian bytes necessary (1, 2, 4, or 8) and returns the number of bytes written.
func (v Nat) EncodeInto(buf Buffer) int {
	switch x := uint64(v); {
	case x <= 0xff:
		buf[0] = byte(x)
		return 1
	case x <= 0xffff:
		binary.BigEndian.PutUint16(buf, uint16(x))
		return 2
	case x <= 0xffffffff:
		binary.BigEndian.PutUint32(buf, uint32(x))
		return 4
	default:
		binary.BigEndian.PutUint64(buf, uint64(x))
		return 8
	}
}

// (AI GENERATED DESCRIPTION): Returns a byte slice containing the encoded representation of the Nat by allocating a buffer sized to its encoding length and writing the Nat into that buffer.
func (v Nat) Bytes() []byte {
	buf := make([]byte, v.EncodingLength())
	v.EncodeInto(buf)
	return buf
}

// (AI GENERATED DESCRIPTION): Parses a big‑endian natural number from a 1, 2, 4, or 8‑byte buffer, returning the value, its length, or an error if the length is unsupported.
func ParseNat(buf Buffer) (val Nat, pos int, err error) {
	switch pos = len(buf); pos {
	case 1:
		val = Nat(buf[0])
	case 2:
		val = Nat(binary.BigEndian.Uint16(buf))
	case 4:
		val = Nat(binary.BigEndian.Uint32(buf))
	case 8:
		val = Nat(binary.BigEndian.Uint64(buf))
	default:
		return 0, 0, ErrFormat{"natural number length is not 1, 2, 4 or 8"}
	}
	return val, pos, nil
}

// Shrink length reduce the L by `shrink“ in a TLV encoded buffer `buf`
//
//	Precondition:
//	  `buf` starts with proper Type and Length numbers.
//	  Length > `shrink`.
//	  May crash otherwise.
//
// Returns the new buffer containing reduced TL header.
// May start from the middle of original buffer, but always goes to the end.
func ShrinkLength(buf Buffer, shrink int) Buffer {
	typ, s1 := ParseTLNum(buf)
	l, s2 := ParseTLNum(buf[s1:])
	newL := l - TLNum(shrink)
	newS2 := newL.EncodingLength()
	if newS2 == s2 {
		newL.EncodeInto(buf[s1:])
		return buf
	} else {
		diff := s2 - newS2
		typ.EncodeInto(buf[diff:])
		newL.EncodeInto(buf[diff+s1:])
		return buf[diff:]
	}
}

// (AI GENERATED DESCRIPTION): Checks whether a rune is an English alphabet letter (either lowercase a‑z or uppercase A‑Z).
func IsAlphabet(r rune) bool {
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
}
