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
	GenMainStruct() (string, error)
	GenMethods() (string, error)
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

func (f *BaseTlvField) Name() string {
	return f.name
}

func (f *BaseTlvField) TypeNum() uint64 {
	return f.typeNum
}

func (*BaseTlvField) GenEncodingLength() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenEncodingWirePlan() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenEncodeInto() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenEncoderStruct() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenInitEncoder() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenParsingContextStruct() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenInitContext() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenReadFrom() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenSkipProcess() (string, error) {
	return "// base - skip", nil
}

func (*BaseTlvField) GenToDict() (string, error) {
	return "", nil
}

func (*BaseTlvField) GenFromDict() (string, error) {
	return "", nil
}

func CreateField(className string, name string, typeNum uint64, annotation string, model *TlvModel) (TlvField, error) {
	fieldList := map[string]func(string, uint64, string, *TlvModel) (TlvField, error){
		"natural":           NewNaturalField,
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
