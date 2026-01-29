package codegen

import (
	"errors"
	"strings"
)

var ErrInvalidField = errors.New("invalid TlvField. Please check the annotation (including type and arguments)")
var ErrWrongTypeNumber = errors.New("invalid type number")

type TlvField interface {
	Name() string
	TypeNum() uint64

	// codegen encoding length of the field
	//   - in(value): struct being encoded
	//   - out(l): length variable to update
	GenEncodingLength() (string, error)
	GenEncodingWirePlan() (string, error)
	GenEncodeInto() (string, error)
	GenEncoderStruct() (string, error)
	GenInitEncoder() (string, error)
	GenParsingContextStruct() (string, error)
	GenInitContext() (string, error)
	GenReadFrom() (string, error)
	GenSkipProcess() (string, error)
	GenToDict() (string, error)
	GenFromDict() (string, error)
}

// BaseTlvField is a base class for all TLV fields.
// Golang's inheritance is not supported, so we use this class to disable
// optional functions.
type BaseTlvField struct {
	name    string
	typeNum uint64
}

// (AI GENERATED DESCRIPTION): Returns the name of the TLV field represented by this BaseTlvField instance.
func (f *BaseTlvField) Name() string {
	return f.name
}

// (AI GENERATED DESCRIPTION): Returns the TLV type number (`typeNum`) stored in the `BaseTlvField` instance.
func (f *BaseTlvField) TypeNum() uint64 {
	return f.typeNum
}

// (AI GENERATED DESCRIPTION): Calculates the length of the BaseTlvField’s TLV encoding and returns it as a string (or an error if the length cannot be determined).
func (*BaseTlvField) GenEncodingLength() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates an encoding wire‑plan string for a BaseTlvField, returning that string and an error if plan generation fails.
func (*BaseTlvField) GenEncodingWirePlan() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates and returns the binary TLV encoding of the BaseTlvField as a string, producing an error if the encoding process fails.
func (*BaseTlvField) GenEncodeInto() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates an encoder struct string for BaseTlvField; currently returns an empty string and no error.
func (*BaseTlvField) GenEncoderStruct() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Initializes the encoder for a BaseTlvField, returning an empty string and nil error.
func (*BaseTlvField) GenInitEncoder() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates the parsing‑context struct string for a BaseTlvField, which currently returns an empty string and no error.
func (*BaseTlvField) GenParsingContextStruct() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates the initial context for a `BaseTlvField`, returning an empty string and no error.
func (*BaseTlvField) GenInitContext() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates a Go code snippet to read a BaseTlvField from a TLV‑encoded payload.
func (*BaseTlvField) GenReadFrom() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates a comment (“// base - skip”) indicating that processing of the base TLV field should be skipped.
func (*BaseTlvField) GenSkipProcess() (string, error) {
	return "// base - skip", nil
}

// (AI GENERATED DESCRIPTION): Generates a dictionary‑formatted string representation of the BaseTlvField, returning any error that occurs during the conversion.
func (*BaseTlvField) GenToDict() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Generates a TLV‑encoded string from the BaseTlvField’s internal dictionary representation.
func (*BaseTlvField) GenFromDict() (string, error) {
	return "", nil
}

// (AI GENERATED DESCRIPTION): Creates a TlvField by mapping the class name prefix to its corresponding constructor, returning an error if the field type is unsupported.
func CreateField(className string, name string, typeNum uint64, annotation string, model *TlvModel) (TlvField, error) {
	fieldList := map[string]func(string, uint64, string, *TlvModel) (TlvField, error){
		"natural":           NewNaturalField,
		"byte":              NewByteField,
		"fixedUint":         NewFixedUintField,
		"time":              NewTimeField,
		"binary":            NewBinaryField,
		"string":            NewStringField,
		"wire":              NewWireField,
		"name":              NewNameField,
		"bool":              NewBoolField,
		"procedureArgument": NewProcedureArgument,
		"offsetMarker":      NewOffsetMarker,
		"rangeMarker":       NewRangeMarker,
		"sequence":          NewSequenceField,
		"struct":            NewStructField,
		"signature":         NewSignatureField,
		"interestName":      NewInterestNameField,
		"map":               NewMapField,
	}

	for k, f := range fieldList {
		if strings.HasPrefix(className, k) {
			return f(name, typeNum, annotation, model)
		}
	}
	return nil, ErrInvalidField
}
