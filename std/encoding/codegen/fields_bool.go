package codegen

import "fmt"

// BoolField represents a boolean field.
type BoolField struct {
	BaseTlvField
}

// (AI GENERATED DESCRIPTION): Creates a BoolField with the specified name and type number and returns it as a TlvField.
func NewBoolField(name string, typeNum uint64, _ string, _ *TlvModel) (TlvField, error) {
	return &BoolField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates Go code that computes the encoding length of a BoolField by adding the type number and zero‑length value bytes only when the field’s boolean value is true.
func (f *BoolField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenTypeNumLen(0))
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates an encoding plan for a BoolField by delegating to its GenEncodingLength method.
func (f *BoolField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

// (AI GENERATED DESCRIPTION): Generates code that, when executed, encodes a BoolField as a zero‑length TLV only if the field’s value is true, writing the field’s type number followed by a zero length.
func (f *BoolField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenEncodeTypeNum(0))
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that sets the Boolean field to true and skips over the field’s payload bytes during deserialization.
func (f *BoolField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("value.%s = true", f.name)
	g.printlnf("err = reader.Skip(int(l))")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a line of code that assigns `false` to the named boolean field when processing is skipped.
func (f *BoolField) GenSkipProcess() (string, error) {
	return fmt.Sprintf("value.%s = false", f.name), nil
}
