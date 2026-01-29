package codegen

import (
	"fmt"
	"strings"
	"text/template"
)

// StructField represents a struct field of another TlvModel.
type StructField struct {
	BaseTlvField

	StructType  string
	innerNoCopy bool
}

// (AI GENERATED DESCRIPTION): Creates a new StructField by parsing the annotation into a struct type and optional “nocopy” flag, validating that the flag is permitted by the model, and initializing the field with the supplied name and type number.
func NewStructField(name string, typeNum uint64, annotation string, model *TlvModel) (TlvField, error) {
	if annotation == "" {
		return nil, ErrInvalidField
	}
	strs := strings.Split(annotation, ":")
	structType := strs[0]
	innerNoCopy := false
	if len(strs) > 1 && strs[1] == "nocopy" {
		innerNoCopy = true
	}
	if !model.NoCopy && innerNoCopy {
		return nil, ErrInvalidField
	}
	return &StructField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		StructType:  structType,
		innerNoCopy: innerNoCopy,
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates the Go code snippet declaring an encoder variable named `<field_name>_encoder` of type `<StructType>Encoder`.
func (f *StructField) GenEncoderStruct() (string, error) {
	return fmt.Sprintf("%s_encoder %sEncoder", f.name, f.StructType), nil
}

// (AI GENERATED DESCRIPTION): Generates Go code that initializes a sub‑encoder for a struct field when the field’s value is non‑nil.
func (f *StructField) GenInitEncoder() (string, error) {
	var templ = template.Must(template.New("StructInitEncoder").Parse(`
		if value.{{.}} != nil {
			encoder.{{.}}_encoder.Init(value.{{.}})
		}
	`))
	var g strErrBuf
	g.executeTemplate(templ, f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a declaration string for a parsing‑context field by concatenating the struct field’s name and type into the form “\<name\>_context \<Type\>ParsingContext”.
func (f *StructField) GenParsingContextStruct() (string, error) {
	return fmt.Sprintf("%s_context %sParsingContext", f.name, f.StructType), nil
}

// (AI GENERATED DESCRIPTION): Generates the Go statement that initializes the context for the struct field.
func (f *StructField) GenInitContext() (string, error) {
	return fmt.Sprintf("context.%s_context.Init()", f.name), nil
}

// (AI GENERATED DESCRIPTION): Generates code that, when a struct field is non‑nil, adds its type number, length prefix, and nested encoder length to the total encoding size.
func (f *StructField) GenEncodingLength() (string, error) {
	var g strErrBuf
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen(fmt.Sprintf("encoder.%s_encoder.Length", f.name), true))
	g.printlnf("l += encoder.%s_encoder.Length", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code to compute the wire‑length of a struct field during encoding, handling nested encoders and inner no‑copy logic.
func (f *StructField) GenEncodingWirePlan() (string, error) {
	if f.innerNoCopy {
		var g strErrBuf
		g.printlnf("if value.%s != nil {", f.name)
		g.printlne(GenTypeNumLen(f.typeNum))
		g.printlne(GenNaturalNumberLen(fmt.Sprintf("encoder.%s_encoder.Length", f.name), true))
		g.printlnf("if encoder.%s_encoder.Length > 0 {", f.name)
		// wirePlan[0] is always nonzero.
		g.printlnf("l += encoder.%s_encoder.wirePlan[0]", f.name)
		g.printlnf("for i := 1; i < len(encoder.%s_encoder.wirePlan); i ++ {", f.name)
		g.printlne(GenSwitchWirePlan())
		g.printlnf("l = encoder.%s_encoder.wirePlan[i]", f.name)
		g.printlnf("}")
		// If l == 0 then inner struct ends with a Wire. So we cannot continue.
		// Otherwise, continue on the last part of the inner wire.
		// Therefore, if the inner structure only uses 1 buf (i.e. with no Wire field),
		// the outer structure will not create extra buffers.
		g.printlnf("if l == 0 {")
		g.printlne(GenSwitchWirePlan())
		g.printlnf("}")
		g.printlnf("}")
		g.printlnf("}")
		return g.output()
	} else {
		return f.GenEncodingLength()
	}
}

// (AI GENERATED DESCRIPTION): Generates a code block that encodes a non‑nil struct field into a buffer, emitting type and length prefixes and performing either a direct encode or an in‑place nested encode to avoid copying.
func (f *StructField) GenEncodeInto() (string, error) {
	var g strErrBuf
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenNaturalNumberEncode(fmt.Sprintf("encoder.%s_encoder.Length", f.name), true))
	g.printlnf("if encoder.%s_encoder.Length > 0 {", f.name)
	if !f.innerNoCopy {
		g.printlnf("encoder.%s_encoder.EncodeInto(value.%s, buf[pos:])", f.name, f.name)
		g.printlnf("pos += encoder.%s_encoder.Length", f.name)
	} else {
		templ := template.Must(template.New("StructEncodeInto").Parse(`{
			subWire := make(enc.Wire, len(encoder.{{.}}_encoder.wirePlan))
			subWire[0] = buf[pos:]
			for i := 1; i < len(subWire); i ++ {
				subWire[i] = wire[wireIdx + i]
			}
			encoder.{{.}}_encoder.EncodeInto(value.{{.}}, subWire)
			for i := 1; i < len(subWire); i ++ {
				wire[wireIdx + i] = subWire[i]
			}
			if lastL := encoder.{{.}}_encoder.wirePlan[len(subWire)-1]; lastL > 0 {
				wireIdx += len(subWire) - 1
				if len(subWire) > 1 {
					pos = lastL
				} else {
					pos += lastL
				}
			} else {
				wireIdx += len(subWire)
				pos = 0
			}
			if wireIdx < len(wire) {
				buf = wire[wireIdx]
			} else {
				buf = nil
			}
		}`))
		g.executeTemplate(templ, f.name)
	}
	g.printlnf("}")
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates code that assigns `nil` to the struct field named `f.name`, thereby skipping its processing.
func (f *StructField) GenSkipProcess() (string, error) {
	return fmt.Sprintf("value.%s = nil", f.name), nil
}

// (AI GENERATED DESCRIPTION): Generates code that reads and parses a struct field’s value from a reader using the field’s context, assigning the parsed result to the struct and capturing any error.
func (f *StructField) GenReadFrom() (string, error) {
	return fmt.Sprintf(
		"value.%[1]s, err = context.%[1]s_context.Parse(reader.Delegate(int(l)), ignoreCritical)",
		f.name,
	), nil
}
