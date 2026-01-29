package encoding

import (
	"bytes"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
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

var DISABLE_ALT_URI = os.Getenv("NDN_NAME_ALT_URI") == "0"

type Component struct {
	Typ TLNum
	Val []byte
}

// (AI GENERATED DESCRIPTION): Returns the receiver component as a `ComponentPattern`, allowing it to satisfy the `ComponentPattern` interface.
func (c Component) ComponentPatternTrait() ComponentPattern {
	return c
}

// (AI GENERATED DESCRIPTION): Creates a copy of a Component, duplicating its type and cloning the underlying value slice.
func (c Component) Clone() Component {
	return Component{
		Typ: c.Typ,
		Val: slices.Clone(c.Val),
	}
}

// (AI GENERATED DESCRIPTION): Returns the byte length of a Component’s value as a TLNum.
func (c Component) Length() TLNum {
	return TLNum(len(c.Val))
}

// (AI GENERATED DESCRIPTION): Returns the serialized string representation of the Component.
func (c Component) String() string {
	sb := strings.Builder{}
	c.WriteTo(&sb)
	return sb.String()
}

// (AI GENERATED DESCRIPTION): Writes a component’s type and value into the supplied `strings.Builder` as a `type=value` pair—using a special formatter for known component types (or numeric type IDs if alternative URI formatting is disabled)—and returns the number of bytes written.
func (c Component) WriteTo(sb *strings.Builder) int {
	size := 0

	vFmt := compValFmt(compValFmtText{})
	if conv, ok := compConvByType[c.Typ]; !DISABLE_ALT_URI && ok {
		vFmt = conv.vFmt
		typ := conv.name
		sb.WriteString(typ)
		sb.WriteRune('=')
		size += len(typ) + 1
	} else if DISABLE_ALT_URI || c.Typ != TypeGenericNameComponent {
		typ := strconv.FormatUint(uint64(c.Typ), 10)
		sb.WriteString(typ)
		sb.WriteRune('=')
		size += len(typ) + 1
	}

	size += vFmt.WriteTo(c.Val, sb)
	return size
}

// (AI GENERATED DESCRIPTION): Returns a canonical string representation of a name component, prefixing the component type number and “=” for non‑generic types and then appending the component’s value formatted as text.
func (c Component) CanonicalString() string {
	sb := strings.Builder{}
	if c.Typ != TypeGenericNameComponent {
		sb.WriteString(strconv.FormatUint(uint64(c.Typ), 10))
		sb.WriteRune('=')
	}
	compValFmtText{}.WriteTo(c.Val, &sb)
	return sb.String()
}

// (AI GENERATED DESCRIPTION): Constructs a Name consisting of this component followed by the provided components.
func (c Component) Append(rest ...Component) Name {
	return Name{c}.Append(rest...)
}

// (AI GENERATED DESCRIPTION): Calculates the total byte length needed to encode a component by adding the length of its type, the length of its value’s length field, and the value’s own byte length.
func (c Component) EncodingLength() int {
	l := len(c.Val)
	return c.Typ.EncodingLength() + Nat(l).EncodingLength() + l
}

// (AI GENERATED DESCRIPTION): Encodes a component's type and value into the supplied buffer—writing the type, the value’s length, and the value bytes—and returns the total number of bytes written.
func (c Component) EncodeInto(buf Buffer) int {
	p1 := c.Typ.EncodeInto(buf)
	p2 := Nat(len(c.Val)).EncodeInto(buf[p1:])
	copy(buf[p1+p2:], c.Val)
	return p1 + p2 + len(c.Val)
}

// (AI GENERATED DESCRIPTION): Returns the fully encoded byte slice representation of the Component.
func (c Component) Bytes() []byte {
	buf := make([]byte, c.EncodingLength())
	c.EncodeInto(buf)
	return buf
}

// (AI GENERATED DESCRIPTION): Compares this Component to another ComponentPattern, returning –1, 0, or 1 according to component type, value length, and byte‑wise value ordering, with Components always considered less than non‑Component patterns.
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
	xx := xxHashPool.Get()
	defer xxHashPool.Put(xx)

	size := c.EncodingLength()
	xx.buffer.Grow(size)
	buf := xx.buffer.AvailableBuffer()[:size]
	c.EncodeInto(buf)

	xx.hash.Write(buf)
	return xx.hash.Sum64()
}

// (AI GENERATED DESCRIPTION): Compares a Component with another ComponentPattern for equality by checking type and value, correctly handling both value and pointer implementations of Component.
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

// (AI GENERATED DESCRIPTION): Matches the receiver Component against the provided value and records any match results in the supplied Matching object.
func (Component) Match(value Component, m Matching) {}

// (AI GENERATED DESCRIPTION): Creates a new Component instance from the current component, ignoring the supplied matching argument.
func (c Component) FromMatching(m Matching) (*Component, error) {
	return &c, nil
}

// (AI GENERATED DESCRIPTION): Determines whether the component matches another component by value equality.
func (c Component) IsMatch(value Component) bool {
	return c.Equal(value)
}

// (AI GENERATED DESCRIPTION): Parses the given string into a Component value, returning the parsed component and an error if the string cannot be interpreted as a component.
func ComponentFromStr(s string) (Component, error) {
	ret := Component{}
	err := componentFromStrInto(s, &ret)
	if err != nil {
		return Component{}, err
	} else {
		return ret, nil
	}
}

// (AI GENERATED DESCRIPTION): Parses a byte slice into a Component by creating a BufferView and reading the component, returning the Component and any parsing error.
func ComponentFromBytes(buf []byte) (Component, error) {
	r := NewBufferView(buf)
	return r.ReadComponent()
}

// (AI GENERATED DESCRIPTION): Parses a TLV‑encoded component from the supplied buffer, extracting its type and value and returning the component together with the total number of bytes consumed.
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

// (AI GENERATED DESCRIPTION): Reads a TLV component from the WireView, decoding its type and length then returning the component’s type and value.
func (r *WireView) ReadComponent() (Component, error) {
	typ, err := r.ReadTLNum()
	if err != nil {
		return Component{}, err
	}
	l, err := r.ReadTLNum()
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

// (AI GENERATED DESCRIPTION): Parses a component type string into its TLNum identifier and associated value format, returning an error if the string is invalid or unrecognized.
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

// (AI GENERATED DESCRIPTION): Parses a string representation of a name component—optionally prefixed by a type name before “=”—into a Component struct, validating the type and converting the value accordingly.
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
