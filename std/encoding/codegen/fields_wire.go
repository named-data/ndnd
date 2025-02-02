package codegen

import (
	"fmt"
	"text/template"
)

// WireField represents a binary string field of type Wire or [][]byte.
type WireField struct {
	BaseTlvField

	noCopy bool
}

func NewWireField(name string, typeNum uint64, _ string, model *TlvModel) (TlvField, error) {
	return &WireField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		noCopy: model.NoCopy,
	}, nil
}

func (f *WireField) GenMainStruct() (string, error) {
	return fmt.Sprintf("%s enc.Wire", f.name), nil
}

func (f *WireField) GenEncoderStruct() (string, error) {
	return fmt.Sprintf("%s_length uint", f.name), nil
}

func (f *WireField) GenInitEncoder() (string, error) {
	templ := template.Must(template.New("WireInitEncoder").Parse(`
		if value.{{.}} != nil {
			encoder.{{.}}_length = 0
			for _, c := range value.{{.}} {
				encoder.{{.}}_length += uint(len(c))
			}
		}
	`))

	var g strErrBuf
	g.executeTemplate(templ, f.name)
	return g.output()
}

func (f *WireField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen("encoder."+f.name+"_length", true))
	g.printlnf("l += encoder.%s_length", f.name)
	g.printlnf("}")
	return g.output()
}

func (f *WireField) GenEncodingWirePlan() (string, error) {
	if f.noCopy {
		g := strErrBuf{}
		g.printlnf("if value.%s != nil {", f.name)
		g.printlne(GenTypeNumLen(f.typeNum))
		g.printlne(GenNaturalNumberLen("encoder."+f.name+"_length", true))
		g.printlne(GenSwitchWirePlan())
		g.printlnf("for range value.%s {", f.name)
		g.printlne(GenSwitchWirePlan())
		g.printlnf("}")
		g.printlnf("}")
		return g.output()
	} else {
		return f.GenEncodingLength()
	}
}

func (f *WireField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenNaturalNumberEncode("encoder."+f.name+"_length", true))
	if f.noCopy {
		g.printlne(GenSwitchWire())
		g.printlnf("for _, w := range value.%s {", f.name)
		g.printlnf("wire[wireIdx] = w")
		g.printlne(GenSwitchWire())
		g.printlnf("}")
	} else {
		g.printlnf("for _, w := range value.%s {", f.name)
		g.printlnf("copy(buf[pos:], w)")
		g.printlnf("pos += uint(len(w))")
		g.printlnf("}")
	}
	g.printlnf("}")
	return g.output()
}

func (f *WireField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("value.%s, err = reader.ReadWire(int(l))", f.name)
	return g.output()
}

func (f *WireField) GenSkipProcess() (string, error) {
	return "value." + f.name + " = nil", nil
}
