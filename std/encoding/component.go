package encoding

import (
	"bytes"
	"hash"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/cespare/xxhash"
)

const (
	TypeInvalidComponent                TLNum = 0x00
	TypeImplicitSha256DigestComponent   TLNum = 0x01
	TypeParametersSha256DigestComponent TLNum = 0x02
	TypeGenericNameComponent            TLNum = 0x08
	TypeKeywordNameComponent            TLNum = 0x20
	TypeSegmentNameComponent            TLNum = 0x32
	TypeByteOffsetNameComponent         TLNum = 0x34
	TypeVersionNameComponent            TLNum = 0x36
	TypeTimestampNameComponent          TLNum = 0x38
	TypeSequenceNumNameComponent        TLNum = 0x3a
)

const (
	ParamShaNameConvention  = "params-sha256"
	DigestShaNameConvention = "sha256digest"
)

var (
	HEX_LOWER = []rune("0123456789abcdef")
	HEX_UPPER = []rune("0123456789ABCDEF")
)

var hashPool = sync.Pool{
	New: func() any { return xxhash.New() },
}

type Component struct {
	Typ TLNum
	Val []byte
}

func (c Component) ComponentPatternTrait() ComponentPattern {
	return c
}

func (c Component) Clone() Component {
	return Component{
		Typ: c.Typ,
		Val: append([]byte(nil), c.Val...),
	}
}

func (c Component) Length() TLNum {
	return TLNum(len(c.Val))
}

func (c Component) String() string {
	sb := strings.Builder{}
	c.WriteTo(&sb)
	return sb.String()
}

func (c Component) WriteTo(sb *strings.Builder) int {
	size := 0

	vFmt := compValFmt(compValFmtText{})
	if conv, ok := compConvByType[c.Typ]; ok {
		vFmt = conv.vFmt
		typ := conv.name
		sb.WriteString(typ)
		sb.WriteRune('=')
		size += len(typ) + 1
	} else if c.Typ != TypeGenericNameComponent {
		typ := strconv.FormatUint(uint64(c.Typ), 10)
		sb.WriteString(typ)
		sb.WriteRune('=')
		size += len(typ) + 1
	}

	size += vFmt.WriteTo(c.Val, sb)
	return size
}

func (c Component) CanonicalString() string {
	sb := strings.Builder{}
	if c.Typ != TypeGenericNameComponent {
		sb.WriteString(strconv.FormatUint(uint64(c.Typ), 10))
		sb.WriteRune('=')
	}
	compValFmtText{}.WriteTo(c.Val, &sb)
	return sb.String()
}

func (c Component) Append(rest ...Component) Name {
	return Name{c}.Append(rest...)
}

func (c Component) EncodingLength() int {
	l := len(c.Val)
	return c.Typ.EncodingLength() + Nat(l).EncodingLength() + l
}

func (c Component) EncodeInto(buf Buffer) int {
	p1 := c.Typ.EncodeInto(buf)
	p2 := Nat(len(c.Val)).EncodeInto(buf[p1:])
	copy(buf[p1+p2:], c.Val)
	return p1 + p2 + len(c.Val)
}

func (c Component) Bytes() []byte {
	buf := make([]byte, c.EncodingLength())
	c.EncodeInto(buf)
	return buf
}

func (c Component) Compare(rhs ComponentPattern) int {
	rc, ok := rhs.(Component)
	if !ok {
		p, ok := rhs.(*Component)
		if !ok {
			// Component is always less than pattern
			return -1
		}
		rc = *p
	}
	if c.Typ != rc.Typ {
		if c.Typ < rc.Typ {
			return -1
		} else {
			return 1
		}
	}
	if len(c.Val) != len(rc.Val) {
		if len(c.Val) < len(rc.Val) {
			return -1
		} else {
			return 1
		}
	}
	return bytes.Compare(c.Val, rc.Val)
}

// NumberVal returns the value of the component as a number
func (c Component) NumberVal() uint64 {
	ret := uint64(0)
	for _, v := range c.Val {
		ret = (ret << 8) | uint64(v)
	}
	return ret
}

// Hash returns the hash of the component
func (c Component) Hash() uint64 {
	h := hashPool.Get().(hash.Hash64)
	defer hashPool.Put(h)
	h.Reset()
	h.Write(c.Bytes())
	return h.Sum64()
}

func (c Component) Equal(rhs ComponentPattern) bool {
	// Go's strange design leads the the result that both Component and *Component implements this interface
	// And it is nearly impossible to predict what is what.
	// So we have to try to cast twice to get the correct result.
	rc, ok := rhs.(Component)
	if !ok {
		p, ok := rhs.(*Component)
		if !ok {
			return false
		}
		rc = *p
	}
	if c.Typ != rc.Typ || len(c.Val) != len(rc.Val) {
		return false
	}
	return bytes.Equal(c.Val, rc.Val)
}

func (Component) Match(value Component, m Matching) {}

func (c Component) FromMatching(m Matching) (*Component, error) {
	return &c, nil
}

func (c Component) IsMatch(value Component) bool {
	return c.Equal(value)
}

func ComponentFromStr(s string) (Component, error) {
	ret := Component{}
	err := componentFromStrInto(s, &ret)
	if err != nil {
		return Component{}, err
	} else {
		return ret, nil
	}
}

func ComponentFromBytes(buf []byte) (Component, error) {
	return ReadComponent(NewBufferReader(buf))
}

func ParseComponent(buf Buffer) (Component, int) {
	typ, p1 := ParseTLNum(buf)
	l, p2 := ParseTLNum(buf[p1:])
	start := p1 + p2
	end := start + int(l)
	return Component{
		Typ: typ,
		Val: buf[start:end],
	}, end
}

func ReadComponent(r ParseReader) (Component, error) {
	typ, err := ReadTLNum(r)
	if err != nil {
		return Component{}, err
	}
	l, err := ReadTLNum(r)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Component{}, err
	}
	val, err := r.ReadBuf(int(l))
	if err != nil {
		return Component{}, err
	}
	return Component{
		Typ: typ,
		Val: val,
	}, nil
}

func ReadComponentFast(r FastReader) (Component, error) {
	typ, err := ReadTLNumFast(r)
	if err != nil {
		return Component{}, err
	}
	l, err := ReadTLNumFast(r)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Component{}, err
	}
	val, err := r.ReadBuf(int(l))
	if err != nil {
		return Component{}, err
	}
	return Component{
		Typ: typ,
		Val: val,
	}, nil
}

func parseCompTypeFromStr(s string) (TLNum, compValFmt, error) {
	if IsAlphabet(rune(s[0])) {
		if conv, ok := compConvByStr[s]; ok {
			return conv.typ, conv.vFmt, nil
		} else {
			return 0, compValFmtInvalid{}, ErrFormat{"unknown component type: " + s}
		}
	} else {
		typInt, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, compValFmtInvalid{}, ErrFormat{"invalid component type: " + s}
		}
		return TLNum(typInt), compValFmtText{}, nil
	}
}

func componentFromStrInto(s string, ret *Component) error {
	var err error
	hasEq := false
	typStr := ""
	valStr := s
	for i, c := range s {
		if c == '=' {
			if !hasEq {
				typStr = s[:i]
				valStr = s[i+1:]
			} else {
				return ErrFormat{"too many '=' in component: " + s}
			}
			hasEq = true
		}
	}
	ret.Typ = TypeGenericNameComponent
	vFmt := compValFmt(compValFmtText{})
	ret.Val = []byte(nil)
	if hasEq {
		ret.Typ, vFmt, err = parseCompTypeFromStr(typStr)
		if err != nil {
			return err
		}
		if ret.Typ <= TypeInvalidComponent || ret.Typ > 0xffff {
			return ErrFormat{"invalid component type: " + valStr}
		}
	}
	ret.Val, err = vFmt.FromString(valStr)
	if err != nil {
		return err
	}
	return nil
}
