package codegen

import (
	"fmt"
	"text/template"
)

// NameField represents a name field.
type NameField struct {
	BaseTlvField
}

func NewNameField(name string, typeNum uint64, _ string, _ *TlvModel) (TlvField, error) {
	return &NameField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
	}, nil
}

func (f *NameField) GenEncoderStruct() (string, error) {
	return fmt.Sprintf("%s_length uint", f.name), nil
}

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

func (f *NameField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen(fmt.Sprintf("encoder.%s_length", f.name), true))
	g.printlnf("l += encoder.%s_length", f.name)
	g.printlnf("}")
	return g.output()
}

func (f *NameField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

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

func (f *NameField) GenReadFrom() (string, error) {
	const Temp = `value.{{.Name}}, err = enc.ReadNameFast(reader.Delegate(int(l)))`
	t := template.Must(template.New("NameEncodeInto").Parse(Temp))
	var g strErrBuf
	g.executeTemplate(t, f)
	return g.output()
}

func (f *NameField) GenSkipProcess() (string, error) {
	return "value." + f.name + " = nil", nil
}
