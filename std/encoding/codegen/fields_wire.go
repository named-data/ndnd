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

// (AI GENERATED DESCRIPTION): Creates a new WireField with the specified name and type number, copying the model’s NoCopy setting to determine whether the field’s bytes should be copied, and returns it.
func NewWireField(name string, typeNum uint64, _ string, model *TlvModel) (TlvField, error) {
	return &WireField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		noCopy: model.NoCopy,
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates a string declaring a uint field named `<wireField>_length` to be included in an encoder struct.
func (f *WireField) GenEncoderStruct() (string, error) {
	return fmt.Sprintf("%s_length uint", f.name), nil
}

// (AI GENERATED DESCRIPTION): Generates Go code that, during packet encoding, sums the byte lengths of each element in a field’s slice and assigns that total to the encoder’s corresponding length field.
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

// (AI GENERATED DESCRIPTION): Generates Go code that, when run, adds the encoding length of the field to the total length only if the field is non‑nil.
func (f *WireField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen("encoder."+f.name+"_length", true))
	g.printlnf("l += encoder.%s_length", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the Go code snippet that encodes a field into the wire format, inserting length prefixes and looping over elements when `noCopy` is set, otherwise just producing the encoding‑length calculation.
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

// (AI GENERATED DESCRIPTION): Generates code to encode a slice of wire elements, writing the field’s type number, length, and each element’s payload, with an optional copy‑or‑switch optimization.
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

// (AI GENERATED DESCRIPTION): Generates code that reads a wire‑encoded field of length l into the struct’s field and assigns any read error to `err`.
func (f *WireField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("value.%s, err = reader.ReadWire(int(l))", f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a code snippet that assigns `nil` to the specified field, effectively skipping its processing.
func (f *WireField) GenSkipProcess() (string, error) {
	return "value." + f.name + " = nil", nil
}
