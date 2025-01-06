package encoding

import (
	"bytes"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unsafe"

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

var hashPool = sync.Pool{
	New: func() interface{} {
		return xxhash.New()
	},
}

type compValFmt interface {
	ToString(val []byte) string
	FromString(s string) ([]byte, error)
	ToMatching(val []byte) any
	FromMatching(m any) ([]byte, error)
}

type compValFmtInvalid struct{}
type compValFmtText struct{}
type compValFmtDec struct{}
type compValFmtHex struct{}

func (compValFmtInvalid) ToString(val []byte) string {
	return ""
}

func (compValFmtInvalid) FromString(s string) ([]byte, error) {
	return nil, ErrFormat{"Invalid component format"}
}

func (compValFmtInvalid) ToMatching(val []byte) any {
	return nil
}

func (compValFmtInvalid) FromMatching(m any) ([]byte, error) {
	return nil, ErrFormat{"Invalid component format"}
}

func (compValFmtText) ToString(val []byte) string {
	vText := ""
	for _, b := range val {
		if isLegalCompText(b) {
			vText = vText + string(b)
		} else {
			vText = vText + fmt.Sprintf("%%%02X", b)
		}
	}
	return vText
}

func (compValFmtText) FromString(valStr string) ([]byte, error) {
	hasSpecialChar := false
	for _, c := range valStr {
		if c == '%' || c == '=' || c == '/' || c == '\\' {
			hasSpecialChar = true
			break
		}
	}
	if !hasSpecialChar {
		return []byte(valStr), nil
	}

	val := make([]byte, 0, len(valStr))
	for i := 0; i < len(valStr); {
		if isLegalCompText(valStr[i]) {
			val = append(val, valStr[i])
			i++
		} else if valStr[i] == '%' && i+2 < len(valStr) {
			v, err := strconv.ParseUint(valStr[i+1:i+3], 16, 8)
			if err != nil {
				return nil, ErrFormat{"invalid component value: " + valStr}
			}
			val = append(val, byte(v))
			i += 3
		} else {
			// Gracefully accept invalid character
			if valStr[i] != '%' && valStr[i] != '=' && valStr[i] != '/' && valStr[i] != '\\' {
				val = append(val, valStr[i])
				i++
			} else {
				return nil, ErrFormat{"invalid component value: " + valStr}
			}
		}
	}
	return val, nil
}

func (compValFmtText) ToMatching(val []byte) any {
	return val
}

func (compValFmtText) FromMatching(m any) ([]byte, error) {
	ret, ok := m.([]byte)
	if !ok {
		return nil, ErrFormat{"invalid text component value: " + fmt.Sprintf("%v", m)}
	} else {
		return ret, nil
	}
}

func (compValFmtDec) ToString(val []byte) string {
	x := uint64(0)
	for _, b := range val {
		x = (x << 8) | uint64(b)
	}
	return strconv.FormatUint(x, 10)
}

func (compValFmtDec) FromString(s string) ([]byte, error) {
	x, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil, ErrFormat{"invalid decimal component value: " + s}
	}
	ret := make([]byte, Nat(x).EncodingLength())
	Nat(x).EncodeInto(ret)
	return ret, nil
}

func (compValFmtDec) ToMatching(val []byte) any {
	x := uint64(0)
	for _, b := range val {
		x = (x << 8) | uint64(b)
	}
	return x
}

func (compValFmtDec) FromMatching(m any) ([]byte, error) {
	x, ok := m.(uint64)
	if !ok {
		return nil, ErrFormat{"invalid decimal component value: " + fmt.Sprintf("%v", m)}
	}
	ret := make([]byte, Nat(x).EncodingLength())
	Nat(x).EncodeInto(ret)
	return ret, nil
}

func (compValFmtHex) ToString(val []byte) string {
	vText := ""
	for _, b := range val {
		vText = vText + fmt.Sprintf("%02x", b)
	}
	return vText
}

func (compValFmtHex) FromString(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, ErrFormat{"invalid hexadecimal component value: " + s}
	}
	l := len(s) / 2
	val := make([]byte, l)
	for i := 0; i < l; i++ {
		b, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, ErrFormat{"invalid hexadecimal component value: " + s}
		}
		val[i] = byte(b)
	}
	return val, nil
}

func (compValFmtHex) ToMatching(val []byte) any {
	return val
}

func (compValFmtHex) FromMatching(m any) ([]byte, error) {
	ret, ok := m.([]byte)
	if !ok {
		return nil, ErrFormat{"invalid text component value: " + fmt.Sprintf("%v", m)}
	} else {
		return ret, nil
	}
}

type componentConvention struct {
	typ  TLNum
	name string
	vFmt compValFmt
}

var (
	compConvByType = map[TLNum]*componentConvention{
		TypeImplicitSha256DigestComponent: {
			typ:  TypeImplicitSha256DigestComponent,
			name: DigestShaNameConvention,
			vFmt: compValFmtHex{},
		},
		TypeParametersSha256DigestComponent: {
			typ:  TypeParametersSha256DigestComponent,
			name: ParamShaNameConvention,
			vFmt: compValFmtHex{},
		},
		TypeSegmentNameComponent: {
			typ:  TypeSegmentNameComponent,
			name: "seg",
			vFmt: compValFmtDec{},
		},
		TypeByteOffsetNameComponent: {
			typ:  TypeByteOffsetNameComponent,
			name: "off",
			vFmt: compValFmtDec{},
		},
		TypeVersionNameComponent: {
			typ:  TypeVersionNameComponent,
			name: "v",
			vFmt: compValFmtDec{},
		},
		TypeTimestampNameComponent: {
			typ:  TypeTimestampNameComponent,
			name: "t",
			vFmt: compValFmtDec{},
		},
		TypeSequenceNumNameComponent: {
			typ:  TypeSequenceNumNameComponent,
			name: "seq",
			vFmt: compValFmtDec{},
		},
	}
	compConvByStr map[string]*componentConvention
)

type ComponentPattern interface {
	// ComponentPatternTrait returns the type trait of Component or Pattern
	// This is used to make ComponentPattern a union type of Component or Pattern
	// Component | Pattern does not work because we need a mixed list NamePattern
	ComponentPatternTrait() ComponentPattern

	// String returns the string of the component, with naming conventions.
	// Since naming conventions are not standardized, this should not be used for purposes other than logging.
	// please use CanonicalString() for stable string representation.
	String() string

	// CanonicalString returns the string representation of the component without naming conventions.
	CanonicalString() string

	// Compare returns an integer comparing two components lexicographically.
	// It compares the type number first, and then its value.
	// A component is always less than a pattern.
	// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
	Compare(ComponentPattern) int

	// Equal returns the two components/patterns are the same.
	Equal(ComponentPattern) bool

	// IsMatch returns if the Component value matches with the current component/pattern.
	IsMatch(value Component) bool

	// Match matches the current pattern/component with the value, and put the matching into the Matching map.
	Match(value Component, m Matching)

	// FromMatching initiates the pattern from the Matching map.
	FromMatching(m Matching) (*Component, error)
}

type Matching map[string][]byte

type Pattern struct {
	Typ TLNum
	Tag string
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

func (p Pattern) ComponentPatternTrait() ComponentPattern {
	return p
}

func initComponentConventions() {
	compConvByStr = make(map[string]*componentConvention, len(compConvByType))
	for _, c := range compConvByType {
		compConvByStr[c.name] = c
	}
}

func (p Pattern) String() string {
	if p.Typ == TypeGenericNameComponent {
		return "<" + p.Tag + ">"
	} else if conv, ok := compConvByType[p.Typ]; ok {
		return "<" + conv.name + "=" + p.Tag + ">"
	} else {
		return fmt.Sprintf("<%d=%s>", p.Typ, p.Tag)
	}
}

func (p Pattern) CanonicalString() string {
	if p.Typ == TypeGenericNameComponent {
		return "<" + p.Tag + ">"
	} else {
		return fmt.Sprintf("<%d=%s>", p.Typ, p.Tag)
	}
}

func (c Component) Length() TLNum {
	return TLNum(len(c.Val))
}

func isLegalCompText(b byte) bool {
	return IsAlphabet(rune(b)) || unicode.IsDigit(rune(b)) || b == '-' || b == '_' || b == '.' || b == '~'
}

func (c Component) String() string {
	vFmt := compValFmt(compValFmtText{})
	tName := ""
	if conv, ok := compConvByType[c.Typ]; ok {
		vFmt = conv.vFmt
		tName = conv.name + "="
	} else if c.Typ != TypeGenericNameComponent {
		tName = strconv.FormatUint(uint64(c.Typ), 10) + "="
	}
	return tName + vFmt.ToString(c.Val)
}

func (c Component) CanonicalString() string {
	tName := ""
	if c.Typ != TypeGenericNameComponent {
		tName = strconv.FormatUint(uint64(c.Typ), 10) + "="
	}
	return tName + compValFmtText{}.ToString(c.Val)
}

func (c Component) Append(rest ...Component) Name {
	return Name{c}.Append(rest...)
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

func ComponentFromStr(s string) (Component, error) {
	ret := Component{}
	err := componentFromStrInto(s, &ret)
	if err != nil {
		return Component{}, err
	} else {
		return ret, nil
	}
}

func ComponentPatternFromStr(s string) (ComponentPattern, error) {
	if len(s) <= 0 || s[0] != '<' {
		return ComponentFromStr(s)
	}
	if s[len(s)-1] != '>' {
		return nil, ErrFormat{"invalid component pattern: " + s}
	}
	s = s[1 : len(s)-1]
	strs := strings.Split(s, "=")
	if len(strs) > 2 {
		return nil, ErrFormat{"too many '=' in component pattern: " + s}
	}
	if len(strs) == 2 {
		typ, _, err := parseCompTypeFromStr(strs[0])
		if err != nil {
			return nil, err
		}
		return Pattern{
			Typ: typ,
			Tag: strs[1],
		}, nil
	} else {
		return Pattern{
			Typ: TypeGenericNameComponent,
			Tag: strs[0],
		}, nil
	}
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

func ComponentFromBytes(buf []byte) (Component, error) {
	return ReadComponent(NewBufferReader(buf))
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
	c.HashInto(h)
	return h.Sum64()
}

// HashInto hashes the current component into the hasher
func (c Component) HashInto(h hash.Hash) {
	// the double cast here prevents the tbuf slice from escaping to heap.
	ptr := uintptr(unsafe.Pointer(&c.Typ))
	tbuf := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), 8)

	h.Write(tbuf)
	h.Write(c.Val)
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

func (p Pattern) Compare(rhs ComponentPattern) int {
	rp, ok := rhs.(Pattern)
	if !ok {
		p, ok := rhs.(*Pattern)
		if !ok {
			// Pattern is always greater than component
			return 1
		}
		rp = *p
	}
	if p.Typ != rp.Typ {
		if p.Typ < rp.Typ {
			return -1
		} else {
			return 1
		}
	}
	return strings.Compare(p.Tag, rp.Tag)
}

func (p Pattern) Equal(rhs ComponentPattern) bool {
	rp, ok := rhs.(Pattern)
	if !ok {
		p, ok := rhs.(*Pattern)
		if !ok {
			return false
		}
		rp = *p
	}
	return p.Typ == rp.Typ && p.Tag == rp.Tag
}

func NewNumberComponent(typ TLNum, val uint64) Component {
	return Component{
		Typ: typ,
		Val: Nat(val).Bytes(),
	}
}

func NewSegmentComponent(seg uint64) Component {
	return NewNumberComponent(TypeSegmentNameComponent, seg)
}

func NewByteOffsetComponent(off uint64) Component {
	return NewNumberComponent(TypeByteOffsetNameComponent, off)
}

func NewSequenceNumComponent(seq uint64) Component {
	return NewNumberComponent(TypeSequenceNumNameComponent, seq)
}

func NewVersionComponent(v uint64) Component {
	return NewNumberComponent(TypeVersionNameComponent, v)
}

func NewTimestampComponent(t uint64) Component {
	return NewNumberComponent(TypeTimestampNameComponent, t)
}

func NewBytesComponent(typ TLNum, val []byte) Component {
	return Component{
		Typ: typ,
		Val: val,
	}
}

func NewStringComponent(typ TLNum, val string) Component {
	return Component{
		Typ: typ,
		Val: []byte(val),
	}
}

func (Component) Match(value Component, m Matching) {}

func (p Pattern) Match(value Component, m Matching) {
	m[p.Tag] = make([]byte, len(value.Val))
	copy(m[p.Tag], value.Val)
}

func (c Component) FromMatching(m Matching) (*Component, error) {
	return &c, nil
}

func (p Pattern) FromMatching(m Matching) (*Component, error) {
	val, ok := m[p.Tag]
	if !ok {
		return nil, ErrNotFound{p.Tag}
	}
	return &Component{
		Typ: p.Typ,
		Val: []byte(val),
	}, nil
}

func (c Component) IsMatch(value Component) bool {
	return c.Equal(value)
}

func (p Pattern) IsMatch(value Component) bool {
	return p.Typ == value.Typ
}
