package encoding

import "time"

// VersionImmutable is the version number for immutable objects.
// A version number of 0 will be used on the wire.
const VersionImmutable = uint64(0)

// VersionUnixMicro is the version number for objects with a unix timestamp.
// A version number of microseconds since the unix epoch will be used on the wire.
// Current unix time must be positive, or usage will panic.
const VersionUnixMicro = uint64(1<<63 - 16)

// (AI GENERATED DESCRIPTION): Constructs a new Component with the specified TLNum type and raw byte slice value.
func NewBytesComponent(typ TLNum, val []byte) Component {
	return Component{
		Typ: typ,
		Val: val,
	}
}

// (AI GENERATED DESCRIPTION): Creates a Component with the specified TLNum type and a string value encoded into a byte slice.
func NewStringComponent(typ TLNum, val string) Component {
	return Component{
		Typ: typ,
		Val: []byte(val),
	}
}

// (AI GENERATED DESCRIPTION): Creates a new Component with the specified TLNum type, encoding the given uint64 value as a natural-number byte slice.
func NewNumberComponent(typ TLNum, val uint64) Component {
	return Component{
		Typ: typ,
		Val: Nat(val).Bytes(),
	}
}

// (AI GENERATED DESCRIPTION): Creates a generic name component with the supplied string value.
func NewGenericComponent(val string) Component {
	return NewStringComponent(TypeGenericNameComponent, val)
}

// (AI GENERATED DESCRIPTION): Creates a name component of type GenericNameComponent using the supplied byte slice.
func NewGenericBytesComponent(val []byte) Component {
	return NewBytesComponent(TypeGenericNameComponent, val)
}

// (AI GENERATED DESCRIPTION): Creates a keyword name component initialized with the supplied string value.
func NewKeywordComponent(val string) Component {
	return NewStringComponent(TypeKeywordNameComponent, val)
}

// (AI GENERATED DESCRIPTION): Creates a name component that represents a segment number, returning a Component with the given segment value.
func NewSegmentComponent(seg uint64) Component {
	return NewNumberComponent(TypeSegmentNameComponent, seg)
}

// (AI GENERATED DESCRIPTION): Creates a byte‑offset name component with the given offset value.
func NewByteOffsetComponent(off uint64) Component {
	return NewNumberComponent(TypeByteOffsetNameComponent, off)
}

// (AI GENERATED DESCRIPTION): Creates a name component that represents a sequence number, using the supplied uint64 value.
func NewSequenceNumComponent(seq uint64) Component {
	return NewNumberComponent(TypeSequenceNumNameComponent, seq)
}

// (AI GENERATED DESCRIPTION): Creates a name component of type *Version* containing the supplied unsigned integer value.
func NewVersionComponent(v uint64) Component {
	return NewNumberComponent(TypeVersionNameComponent, v)
}

// (AI GENERATED DESCRIPTION): Creates a timestamp name component that holds the supplied 64‑bit unsigned integer.
func NewTimestampComponent(t uint64) Component {
	return NewNumberComponent(TypeTimestampNameComponent, t)
}

// (AI GENERATED DESCRIPTION): Returns true if the component is a generic name component whose value equals the supplied text.
func (c Component) IsGeneric(text string) bool {
	return c.Typ == TypeGenericNameComponent && string(c.Val) == text
}

// (AI GENERATED DESCRIPTION): Checks if the component is a keyword component whose value exactly matches the supplied keyword string.
func (c Component) IsKeyword(keyword string) bool {
	return c.Typ == TypeKeywordNameComponent && string(c.Val) == keyword
}

// (AI GENERATED DESCRIPTION): Determines whether the component represents a segment name component.
func (c Component) IsSegment() bool {
	return c.Typ == TypeSegmentNameComponent
}

// (AI GENERATED DESCRIPTION): Checks whether the component is a byte‑offset name component.
func (c Component) IsByteOffset() bool {
	return c.Typ == TypeByteOffsetNameComponent
}

// (AI GENERATED DESCRIPTION): Checks if the component represents a sequence number (i.e., its type equals `TypeSequenceNumNameComponent`).
func (c Component) IsSequenceNum() bool {
	return c.Typ == TypeSequenceNumNameComponent
}

// (AI GENERATED DESCRIPTION): Checks whether the component’s type indicates it is a version component in a name.
func (c Component) IsVersion() bool {
	return c.Typ == TypeVersionNameComponent
}

// (AI GENERATED DESCRIPTION): Determines whether the component is a timestamp name component.
func (c Component) IsTimestamp() bool {
	return c.Typ == TypeTimestampNameComponent
}

// WithVersion appends a version component to the name.
func (n Name) WithVersion(v uint64) Name {
	if n.At(-1).IsVersion() {
		n = n.Prefix(-1) // pop old version
	}
	switch v {
	case VersionImmutable:
		v = 0
	case VersionUnixMicro:
		if now := time.Now().UnixMicro(); now > 0 { // > 1970
			v = uint64(now)
		} else {
			panic("current unix time is negative")
		}
	}
	return n.Append(NewVersionComponent(v))
}
