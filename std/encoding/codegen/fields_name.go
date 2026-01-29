package codegen

import (
	"fmt"
	"text/template"
)

// NameField represents a name field.
type NameField struct {
	BaseTlvField
}

// (AI GENERATED DESCRIPTION): Creates and returns a NameField TlvField initialized with the provided name and type number.
func NewNameField(name string, typeNum uint64, _ string, _ *TlvModel) (TlvField, error) {
	return &NameField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates a struct field declaration for the length of a `NameField`, returning the string "`<fieldName>_length uint`".
func (f *NameField) GenEncoderStruct() (string, error) {
	return fmt.Sprintf("%s_length uint", f.name), nil
}

// (AI GENERATED DESCRIPTION): Generates code that, when a name field is present, computes and sets the encoder’s length field by summing the encoding lengths of each component of that name.
func (f *NameField) GenInitEncoder() (string, error) {
	var g strErrBuf
	const Temp = `if value.{{.}} != nil {
		encoder.{{.}}_length = 0
		for _, c := range value.{{.}} {
			encoder.{{.}}_length += uint(c.EncodingLength())
		}
	}
	`
	t := template.Must(template.New("NameInitEncoder").Parse(Temp))
	g.executeTemplate(t, f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that calculates the encoded length of a NameField, adding its type number, length prefix, and the field’s own length when the field is set.
func (f *NameField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen(fmt.Sprintf("encoder.%s_length", f.name), true))
	g.printlnf("l += encoder.%s_length", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the wire‑encoding plan for a NameField by delegating to its GenEncodingLength routine.
func (f *NameField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

// (AI GENERATED DESCRIPTION): Generates Go code that serializes a NameField by writing its type number, length, and each component into a byte buffer.
func (f *NameField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenNaturalNumberEncode("encoder."+f.name+"_length", true))
	g.printlnf("for _, c := range value.%s {", f.name)
	g.printlnf("pos += uint(c.EncodeInto(buf[pos:]))")
	g.printlnf("}")
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that reads a name value from a reader into the struct’s Name field.
func (f *NameField) GenReadFrom() (string, error) {
	const Temp = `
		delegate:=reader.Delegate(int(l))
		value.{{.Name}}, err = delegate.ReadName()
	`
	t := template.Must(template.New("NameEncodeInto").Parse(Temp))
	var g strErrBuf
	g.executeTemplate(t, f)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that skips processing a name field by setting the corresponding field in the value struct to nil.
func (f *NameField) GenSkipProcess() (string, error) {
	return "value." + f.name + " = nil", nil
}
