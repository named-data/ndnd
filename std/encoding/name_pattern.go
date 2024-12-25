package encoding

import (
	"crypto/sha256"
	"hash"
	"io"
	"strings"

	"github.com/named-data/ndnd/std/utils"
)

type Name []Component

type NamePattern []ComponentPattern

const TypeName TLNum = 0x07

func (n Name) String() string {
	ret := ""
	for _, c := range n {
		ret += "/" + c.String()
	}
	if len(ret) == 0 {
		ret = "/"
	} else if n[len(n)-1].Typ == TypeGenericNameComponent && len(n[len(n)-1].Val) == 0 {
		ret += "/"
	}
	return ret
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
func (n *Name) Hash() uint64 {
	h := hashPool.Get().(hash.Hash64)
	defer hashPool.Put(h)
	h.Reset()
	for i := range *n {
		(*n)[i].HashInto(h)
	}
	return h.Sum64()
}

// PrefixHash returns the hash value of all prefixes of the name
// ret[n] means the hash of the prefix of length n. ret[0] is the same for all names.
func (n *Name) PrefixHash() []uint64 {
	h := hashPool.Get().(hash.Hash64)
	defer hashPool.Put(h)
	h.Reset()
	ret := make([]uint64, len(*n)+1)
	ret[0] = h.Sum64()
	for i, c := range *n {
		c.HashInto(h)
		ret[i+1] = h.Sum64()
	}
	return ret
}

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

func (n Name) Compare(rhs Name) int {
	for i := 0; i < utils.Min(len(n), len(rhs)); i++ {
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
	for i := 0; i < utils.Min(len(n), len(rhs)); i++ {
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
	if n[len(n)-1].Typ == TypeImplicitSha256DigestComponent {
		return n
	}
	h := sha256.New()
	for _, buf := range rawData {
		h.Write(buf)
	}
	digest := h.Sum(nil)
	ret := append(n, Component{
		Typ: TypeImplicitSha256DigestComponent,
		Val: digest,
	})
	return ret
}
