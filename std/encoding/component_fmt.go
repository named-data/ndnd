package encoding

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type compValFmt interface {
	WriteTo(val []byte, sb *strings.Builder) int
	FromString(s string) ([]byte, error)
	ToMatching(val []byte) any
	FromMatching(m any) ([]byte, error)
}

type compValFmtInvalid struct{}
type compValFmtText struct{}
type compValFmtDec struct{}
type compValFmtHex struct{}

// (AI GENERATED DESCRIPTION): Does nothing for an invalid component value format, returning zero bytes written.
func (compValFmtInvalid) WriteTo(val []byte, sb *strings.Builder) int {
	return 0
}

// (AI GENERATED DESCRIPTION): Parses a string into a component value but always fails, returning nil and an `ErrFormat` error indicating an invalid component format.
func (compValFmtInvalid) FromString(s string) ([]byte, error) {
	return nil, ErrFormat{"Invalid component format"}
}

// (AI GENERATED DESCRIPTION): Returns `nil` to indicate that the component value format is invalid and cannot produce a valid match.
func (compValFmtInvalid) ToMatching(val []byte) any {
	return nil
}

// (AI GENERATED DESCRIPTION): Returns an error indicating that the component format is invalid, preventing serialization of the value.
func (compValFmtInvalid) FromMatching(m any) ([]byte, error) {
	return nil, ErrFormat{"Invalid component format"}
}

// (AI GENERATED DESCRIPTION): Writes a byte slice to the supplied string builder, percent‑encoding any non‑legal component characters and returning the number of bytes written.
func (compValFmtText) WriteTo(val []byte, sb *strings.Builder) int {
	size := 0
	for _, b := range val {
		if isLegalCompText(b) {
			sb.WriteByte(b)
			size += 1
		} else {
			sb.WriteRune('%')
			sb.WriteRune(HEX_UPPER[b>>4])
			sb.WriteRune(HEX_UPPER[b&0x0F])
			size += 3
		}
	}
	return size
}

// (AI GENERATED DESCRIPTION): Converts a component value string into a byte slice, decoding percent‑encoded sequences and rejecting any invalid or improperly escaped characters.
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

// (AI GENERATED DESCRIPTION): Returns the input byte slice unchanged, converting a text‑formatted component value to its matching Go representation.
func (compValFmtText) ToMatching(val []byte) any {
	return val
}

// (AI GENERATED DESCRIPTION): Attempts to convert a generic value to a byte slice for a text component, returning an error if the value is not a `[]byte`.
func (compValFmtText) FromMatching(m any) ([]byte, error) {
	ret, ok := m.([]byte)
	if !ok {
		return nil, ErrFormat{"invalid text component value: " + fmt.Sprintf("%v", m)}
	} else {
		return ret, nil
	}
}

// (AI GENERATED DESCRIPTION): Converts a byte slice representing an unsigned integer into its decimal string form and writes that string into the provided string builder.
func (compValFmtDec) WriteTo(val []byte, sb *strings.Builder) int {
	x := uint64(0)
	for _, b := range val {
		x = (x << 8) | uint64(b)
	}
	vstr := strconv.FormatUint(x, 10)
	sb.WriteString(vstr)
	return len(vstr)
}

// (AI GENERATED DESCRIPTION): Parses a decimal string into an unsigned integer and returns its binary encoding as a byte slice, or an error if the string is not a valid decimal number.
func (compValFmtDec) FromString(s string) ([]byte, error) {
	x, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil, ErrFormat{"invalid decimal component value: " + s}
	}
	ret := make([]byte, Nat(x).EncodingLength())
	Nat(x).EncodeInto(ret)
	return ret, nil
}

// (AI GENERATED DESCRIPTION): Converts a big‑endian encoded byte slice into a uint64 integer value.
func (compValFmtDec) ToMatching(val []byte) any {
	x := uint64(0)
	for _, b := range val {
		x = (x << 8) | uint64(b)
	}
	return x
}

// (AI GENERATED DESCRIPTION): Converts a uint64 decimal component value into its Nat-encoded byte representation, returning an error if the input is not a uint64.
func (compValFmtDec) FromMatching(m any) ([]byte, error) {
	x, ok := m.(uint64)
	if !ok {
		return nil, ErrFormat{"invalid decimal component value: " + fmt.Sprintf("%v", m)}
	}
	ret := make([]byte, Nat(x).EncodingLength())
	Nat(x).EncodeInto(ret)
	return ret, nil
}

// (AI GENERATED DESCRIPTION): Converts a byte slice into a lowercase hexadecimal string, appending the result to a `strings.Builder` and returning the number of runes written.
func (compValFmtHex) WriteTo(val []byte, sb *strings.Builder) int {
	for _, b := range val {
		sb.WriteRune(HEX_LOWER[b>>4])
		sb.WriteRune(HEX_LOWER[b&0x0F])
	}
	return len(val) * 2
}

// (AI GENERATED DESCRIPTION): Converts a hexadecimal-encoded string into its raw byte slice, returning an error if the string has odd length or contains invalid hex characters.
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

// (AI GENERATED DESCRIPTION): Returns the provided byte slice unchanged, serving as the matching value.
func (compValFmtHex) ToMatching(val []byte) any {
	return val
}

// (AI GENERATED DESCRIPTION): Validates a matched value is a []byte and returns it, otherwise returns an error indicating an invalid text component value.
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

// (AI GENERATED DESCRIPTION): Populates the global `compConvByStr` map, mapping each component convention’s name string to its corresponding `componentConvention` struct for quick lookup.
func initComponentConventions() {
	compConvByStr = make(map[string]*componentConvention, len(compConvByType))
	for _, c := range compConvByType {
		compConvByStr[c.name] = c
	}
}

// (AI GENERATED DESCRIPTION): Checks if a byte is a legal character for a name component (letters, digits, hyphen, underscore, dot, or tilde).
func isLegalCompText(b byte) bool {
	return IsAlphabet(rune(b)) || unicode.IsDigit(rune(b)) || b == '-' || b == '_' || b == '.' || b == '~'
}
