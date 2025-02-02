package encoding

import (
	"crypto/sha256"
	"hash"
	"io"
	"strings"
	"unsafe"
)

type Name []Component

type NamePattern []ComponentPattern

const TypeName TLNum = 0x07

const sizeTLNum = int(unsafe.Sizeof(TLNum(0)))
const sizeLen = int(unsafe.Sizeof(len([]byte{})))

func (n Name) String() string {
	sb := strings.Builder{}
	for i, c := range n {
		sb.WriteRune('/')
		sz := c.WriteTo(&sb)
		if i == len(n)-1 && sz == 0 {
			sb.WriteRune('/')
		}
	}
	if sb.Len() == 0 {
		return "/"
	}
	return sb.String()
}

func (n NamePattern) String() string {
	ret := ""
	for _, c := range n {
		ret += "/" + c.String()
	}
	if len(ret) == 0 {
		ret = "/"
	} else {
		if c, ok := n[len(n)-1].(*Component); ok {
			if c.Typ == TypeGenericNameComponent && len(c.Val) == 0 {
				ret += "/"
			}
		}
	}
	return ret
}

// EncodeInto encodes a Name into a Buffer **excluding** the TL prefix.
// Please use Bytes() to get the fully encoded name.
func (n Name) EncodeInto(buf Buffer) int {
	pos := 0
	for _, c := range n {
		pos += c.EncodeInto(buf[pos:])
	}
	return pos
}

// EncodingLength computes a Name's length after encoding **excluding** the TL prefix.
func (n Name) EncodingLength() int {
	ret := 0
	for _, c := range n {
		ret += c.EncodingLength()
	}
	return ret
}

// Clone returns a deep copy of a Name
func (n Name) Clone() Name {
	ret := make(Name, len(n))
	for i, c := range n {
		ret[i] = c.Clone()
	}
	return ret
}

// Get the ith component of a Name.
// If i is out of range, a zero component is returned.
// Negative values start from the end.
func (n Name) At(i int) Component {
	if i < -len(n) || i >= len(n) {
		return Component{}
	} else if i < 0 {
		return n[len(n)+i]
	} else {
		return n[i]
	}
}

// Get a name prefix with the first i components.
// If i is zero, an empty name is returned.
// If i is negative, i components are removed from the end.
// Note that the returned name is not a deep copy.
func (n Name) Prefix(i int) Name {
	if i < 0 {
		i = len(n) + i
	}
	if i <= 0 {
		return Name{}
	}
	if i >= len(n) {
		return n
	}
	return n[:i]
}

// ReadName reads a Name from a Wire **excluding** the TL prefix.
func ReadName(r ParseReader) (Name, error) {
	var err error
	var c Component
	ret := make(Name, 0)
	// Bad design of Go: it does not allow you use := to create a temp var c and write the error to err.
	for c, err = ReadComponent(r); err == nil; c, err = ReadComponent(r) {
		ret = append(ret, c)
	}
	if err != io.EOF {
		return nil, err
	} else {
		return ret, nil
	}
}

// Bytes returns the encoded bytes of a Name
func (n Name) Bytes() []byte {
	l := n.EncodingLength()
	buf := make([]byte, TypeName.EncodingLength()+Nat(l).EncodingLength()+l)
	p1 := TypeName.EncodeInto(buf)
	p2 := Nat(l).EncodeInto(buf[p1:])
	n.EncodeInto(buf[p1+p2:])
	return buf
}

// Hash returns the hash of the name
func (n Name) Hash() uint64 {
	h := hashPool.Get().(hash.Hash64)
	defer hashPool.Put(h)
	h.Reset()
	for _, c := range n {
		c.HashInto(h)
	}
	return h.Sum64()
}

// PrefixHash returns the hash value of all prefixes of the name
// ret[n] means the hash of the prefix of length n. ret[0] is the same for all names.
func (n Name) PrefixHash() []uint64 {
	h := hashPool.Get().(hash.Hash64)
	defer hashPool.Put(h)
	h.Reset()
	ret := make([]uint64, len(n)+1)
	ret[0] = h.Sum64()
	for i, c := range n {
		c.HashInto(h)
		ret[i+1] = h.Sum64()
	}
	return ret
}

// NameFromStr parses a URI string into a Name
func NameFromStr(s string) (Name, error) {
	strs := strings.Split(s, "/")
	// Removing leading and trailing empty strings given by /
	if strs[0] == "" {
		strs = strs[1:]
	}
	if len(strs) > 0 && strs[len(strs)-1] == "" {
		strs = strs[:len(strs)-1]
	}
	ret := make(Name, len(strs))
	for i, str := range strs {
		err := componentFromStrInto(str, &ret[i])
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// NamePatternFromStr parses a string into a NamePattern
func NamePatternFromStr(s string) (NamePattern, error) {
	strs := strings.Split(s, "/")
	// Removing leading and trailing empty strings given by /
	if strs[0] == "" {
		strs = strs[1:]
	}
	if strs[len(strs)-1] == "" {
		strs = strs[:len(strs)-1]
	}
	ret := make(NamePattern, len(strs))
	for i, str := range strs {
		c, err := ComponentPatternFromStr(str)
		if err != nil {
			return nil, err
		}
		ret[i] = c
	}
	return ret, nil
}

// NameFromBytes parses a URI byte slice into a Name
func NameFromBytes(buf []byte) (Name, error) {
	r := NewBufferReader(buf)
	t, err := ReadTLNum(r)
	if err != nil {
		return nil, err
	}
	if t != TypeName {
		return nil, ErrFormat{"encoding.NameFromBytes: given bytes is not a Name"}
	}
	l, err := ReadTLNum(r)
	if err != nil {
		return nil, err
	}
	start := r.Pos()
	ret, err := ReadName(r)
	if err != nil {
		return nil, err
	}
	end := r.Length()
	if int(l) != end-start {
		return nil, ErrFormat{"encoding.NameFromBytes: given bytes have a wrong length"}
	}
	return ret, nil
}

// Append appends one or more components to a shallow copy of the name.
// Using this function is recommended over the in-built `append`.
// A copy will not be created for chained appends.
func (n Name) Append(rest ...Component) Name {
	size := len(n) + len(rest)
	if len(rest) == 0 {
		return n
	}

	var ret Name = nil
	if cap(n) >= size {
		// If the next component is a zero component,
		// we can just reuse the previous buffer.
		prev := n[:size]
		if prev[len(n)].Typ == 0 {
			ret = prev
		}
	}

	if ret == nil {
		// Allocate extra buffer space so that chained appends are faster.
		ret = make(Name, size, size+8)
		copy(ret, n)
	}

	copy(ret[len(n):], rest)
	return ret
}

func (n Name) Compare(rhs Name) int {
	for i := 0; i < min(len(n), len(rhs)); i++ {
		if ret := n[i].Compare(rhs[i]); ret != 0 {
			return ret
		}
	}
	switch {
	case len(n) < len(rhs):
		return -1
	case len(n) > len(rhs):
		return 1
	default:
		return 0
	}
}

func (n NamePattern) Compare(rhs NamePattern) int {
	for i := 0; i < min(len(n), len(rhs)); i++ {
		if ret := n[i].Compare(rhs[i]); ret != 0 {
			return ret
		}
	}
	switch {
	case len(n) < len(rhs):
		return -1
	case len(n) > len(rhs):
		return 1
	default:
		return 0
	}
}

func (n Name) Equal(rhs Name) bool {
	if len(n) != len(rhs) {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !n[i].Equal(rhs[i]) {
			return false
		}
	}
	return true
}

func (n NamePattern) Equal(rhs NamePattern) bool {
	if len(n) != len(rhs) {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !n[i].Equal(rhs[i]) {
			return false
		}
	}
	return true
}

func (n Name) IsPrefix(rhs Name) bool {
	if len(n) > len(rhs) {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !n[i].Equal(rhs[i]) {
			return false
		}
	}
	return true
}

func (n NamePattern) IsPrefix(rhs NamePattern) bool {
	if len(n) > len(rhs) {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !n[i].Equal(rhs[i]) {
			return false
		}
	}
	return true
}

func (n NamePattern) Match(name Name, m Matching) {
	for i, c := range n {
		c.Match(name[i], m)
	}
}

func (n NamePattern) FromMatching(m Matching) (Name, error) {
	ret := make(Name, len(n))
	for i, c := range n {
		comp, err := c.FromMatching(m)
		if err != nil {
			return nil, err
		}
		ret[i] = *comp
	}
	return ret, nil
}

func (n Name) ToFullName(rawData Wire) Name {
	if n.At(-1).Typ == TypeImplicitSha256DigestComponent {
		return n
	}
	h := sha256.New()
	for _, buf := range rawData {
		h.Write(buf)
	}
	digest := h.Sum(nil)
	return n.Append(Component{
		Typ: TypeImplicitSha256DigestComponent,
		Val: digest,
	})
}

// FStr returns a fast reversible string representation of a Name.
// [WARNING] The output must never leave this application's memory.
func (n Name) FStr() string {
	sb := strings.Builder{}
	size := sizeLen // # of components
	for i := range n {
		size += sizeTLNum + sizeLen + len(n[i].Val)
	}
	sb.Grow(size)

	length := len(n)
	sb.Write(unsafe.Slice((*byte)(unsafe.Pointer(&length)), sizeLen))
	for _, c := range n {
		length = len(c.Val)
		sb.Write(unsafe.Slice((*byte)(unsafe.Pointer(&c.Typ)), sizeTLNum))
		sb.Write(unsafe.Slice((*byte)(unsafe.Pointer(&length)), sizeLen))
		sb.Write(c.Val)
	}
	return sb.String()
}

// NameFromFStr parses the output of FStr into a Name.
func NameFromFStr(s string) (Name, error) {
	byts := unsafe.Slice(unsafe.StringData(s), len(s))
	if len(byts) < sizeLen {
		return nil, ErrFormat{"encoding.NameFromFStr (1)"}
	}
	length := *(*int)(unsafe.Pointer(&byts[0]))
	if length < 0 || length > 8192 {
		return nil, ErrFormat{"encoding.NameFromFStr (2)"}
	}
	byts = byts[sizeLen:]

	// outer slice for name
	name := make(Name, length)
	cvalLen := len(byts) - (sizeTLNum+sizeLen)*length
	if cvalLen < 0 {
		return nil, ErrFormat{"encoding.NameFromFStr (3)"}
	}

	// single underlying array for all components
	comps := make([]byte, cvalLen)

	for i := range name {
		if len(byts) < sizeTLNum+sizeLen {
			return nil, ErrFormat{"encoding.NameFromFStr (3)"}
		}
		name[i].Typ = *(*TLNum)(unsafe.Pointer(&byts[0]))
		compLen := *(*int)(unsafe.Pointer(&byts[sizeTLNum]))
		byts = byts[sizeTLNum+sizeLen:]
		if len(byts) < compLen {
			return nil, ErrFormat{"encoding.NameFromFStr: (4)"}
		}
		if len(comps) < compLen {
			return nil, ErrFormat{"encoding.NameFromFStr: (5)"}
		}
		copy(comps, byts[:compLen])
		byts = byts[compLen:]
		name[i].Val = comps[:compLen]
		comps = comps[compLen:]
	}

	return name, nil
}
