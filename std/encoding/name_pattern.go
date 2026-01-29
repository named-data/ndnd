package encoding

import (
	"crypto/sha256"
	"io"
	"strings"
	"unsafe"
)

type Name []Component

type NamePattern []ComponentPattern

const TypeName TLNum = 0x07

// (AI GENERATED DESCRIPTION): Converts a Name into its canonical string form, prefixing each component with a slash and handling empty or root names so that an empty last component is represented by a trailing slash.
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

// (AI GENERATED DESCRIPTION): Generates a string representation of a NamePattern by concatenating each component prefixed with “/”, defaulting to “/” when empty, and appending a trailing slash when the final component is an empty generic name component.
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
	valLen := 0
	for i := range n {
		valLen += len(n[i].Val)
	}
	buf := make([]byte, valLen)
	for i, c := range n {
		ret[i].Typ = c.Typ
		vlen := len(c.Val)
		copy(buf, c.Val)
		ret[i].Val = buf[:vlen]
		buf = buf[vlen:]
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
func (r *WireView) ReadName() (Name, error) {
	var err error
	var c Component
	ret := make(Name, 0, 8)
	// Bad design of Go: it does not allow you use := to create a temp var c and write the error to err.
	for c, err = r.ReadComponent(); err == nil; c, err = r.ReadComponent() {
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

// BytesInner returns the encoded bytes of a Name **excluding** the TL prefix.
func (n Name) BytesInner() []byte {
	buf := make([]byte, n.EncodingLength())
	n.EncodeInto(buf)
	return buf
}

// Hash returns the hash of the name
func (n Name) Hash() uint64 {
	xx := xxHashPool.Get()
	defer xxHashPool.Put(xx)

	size := n.EncodingLength()
	xx.buffer.Grow(size)
	buf := xx.buffer.AvailableBuffer()[:size]
	n.EncodeInto(buf)

	xx.hash.Write(buf)
	return xx.hash.Sum64()
}

// PrefixHash returns the hash value of all prefixes of the name
// ret[n] means the hash of the prefix of length n. ret[0] is the same for all names.
func (n Name) PrefixHash() []uint64 {
	xx := xxHashPool.Get()
	defer xxHashPool.Put(xx)

	ret := make([]uint64, len(n)+1)
	ret[0] = xx.hash.Sum64()
	for i := range n {
		xx.buffer.Reset()
		size := n[i].EncodingLength()
		xx.buffer.Grow(size)
		buf := xx.buffer.AvailableBuffer()[:size]
		n[i].EncodeInto(buf)

		xx.hash.Write(buf)
		ret[i+1] = xx.hash.Sum64()
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
	r := NewBufferView(buf)
	t, err := r.ReadTLNum()
	if err != nil {
		return nil, err
	}
	if t != TypeName {
		return nil, ErrFormat{"encoding.NameFromBytes: given bytes is not a Name"}
	}
	l, err := r.ReadTLNum()
	if err != nil {
		return nil, err
	}
	start := r.Pos()
	ret, err := r.ReadName()
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

// (AI GENERATED DESCRIPTION): Compares two `Name` values lexicographically by sequentially comparing each component, returning –1, 0, or 1 to indicate whether the left name is less than, equal to, or greater than the right name.
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

// (AI GENERATED DESCRIPTION): Compares two `NamePattern` objects lexicographically, returning –1 if the receiver is smaller, 1 if it is larger, or 0 if the two patterns are equal.
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

// (AI GENERATED DESCRIPTION): Determines whether two Name objects represent the same name sequence by comparing their lengths and, if needed, performing component‑wise equality checks.
func (n Name) Equal(rhs Name) bool {
	if len(n) != len(rhs) {
		return false
	}
	if len(n) == 0 || &n[0] == &rhs[0] {
		return true // cheap
	}
	for i := range n {
		if !n[i].Equal(rhs[i]) {
			return false
		}
	}
	return true
}

// (AI GENERATED DESCRIPTION): Checks whether two NamePattern values are equal by comparing their lengths and each corresponding element.
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

// (AI GENERATED DESCRIPTION): Returns true if the name n is a prefix of the given name rhs.
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

// (AI GENERATED DESCRIPTION): Checks whether the receiver NamePattern is a prefix of the specified rhs NamePattern.
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

// (AI GENERATED DESCRIPTION): Matches each component of a NamePattern against the corresponding component of a Name, recording the results in the provided Matching object.
func (n NamePattern) Match(name Name, m Matching) {
	for i, c := range n {
		c.Match(name[i], m)
	}
}

// (AI GENERATED DESCRIPTION): Creates a concrete Name from the NamePattern by applying each component’s matching logic to the supplied Matching context.
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

// (AI GENERATED DESCRIPTION): Adds an implicit SHA‑256 digest component to the name based on the supplied raw data, unless the name already ends with an implicit digest component.
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

// TlvStr returns the TLV encoding of a Component as a string.
// This is a lot faster than converting to a URI string.
func (c Component) TlvStr() string {
	// https://github.com/golang/go/blob/37f27fbecd422da9fefb8ae1cc601bc5b4fec44b/src/strings/builder.go#L39-L42
	buf := c.Bytes()
	return unsafe.String(unsafe.SliceData(buf), len(buf))
}

// TlvStr returns the TLV encoding of a Name as a string.
func (n Name) TlvStr() string {
	buf := n.BytesInner()
	return unsafe.String(unsafe.SliceData(buf), len(buf))
}

// ComponentFromTlvStr parses the output of TlvStr into a Component.
func ComponentFromTlvStr(s string) (Component, error) {
	r := NewBufferView([]byte(s))
	return r.ReadComponent()
}

// NameFromFStr parses the output of FStr into a Name.
func NameFromTlvStr(s string) (Name, error) {
	r := NewBufferView([]byte(s))
	return r.ReadName()
}
