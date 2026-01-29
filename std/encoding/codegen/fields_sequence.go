package codegen

import (
	"fmt"
	"strings"
	"text/template"
)

// SequenceField represents a slice field of another supported field type.
type SequenceField struct {
	BaseTlvField

	SubField  TlvField
	FieldType string
}

// (AI GENERATED DESCRIPTION): Creates a SequenceField TLV that wraps a subfield defined by the annotation string, using the supplied name and type number.
func NewSequenceField(name string, typeNum uint64, annotation string, model *TlvModel) (TlvField, error) {
	strs := strings.SplitN(annotation, ":", 3)
	if len(strs) < 2 {
		return nil, ErrInvalidField
	}
	subFieldType := strs[0]
	subFieldClass := strs[1]
	if len(strs) >= 3 {
		annotation = strs[2]
	} else {
		annotation = ""
	}
	subField, err := CreateField(subFieldClass, name, typeNum, annotation, model)
	if err != nil {
		return nil, err
	}
	return &SequenceField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		SubField:  subField,
		FieldType: subFieldType,
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates the Go struct declaration for a sequence field’s encoder, producing a slice of anonymous structs each containing the subfield’s encoding.
func (f *SequenceField) GenEncoderStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s_subencoder []struct{", f.name)
	g.printlne(f.SubField.GenEncoderStruct())
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the code to initialize a sequence field’s encoder by allocating a slice of sub‑field encoders and iterating over each element to set up pseudo encoders and values for encoding.
func (f *SequenceField) GenInitEncoder() (string, error) {
	// Sequence uses faked encoder variable to embed the subfield.
	// I have verified that the Go compiler can optimize this in simple cases.
	templ := template.Must(template.New("SeqInitEncoder").Parse(`
		{
			{{.Name}}_l := len(value.{{.Name}})
			encoder.{{.Name}}_subencoder = make([]struct{
				{{.SubField.GenEncoderStruct}}
			}, {{.Name}}_l)
			for i := 0; i < {{.Name}}_l; i ++ {
				pseudoEncoder := &encoder.{{.Name}}_subencoder[i]
				pseudoValue := struct {
					{{.Name}} {{.FieldType}}
				}{
					{{.Name}}: value.{{.Name}}[i],
				}
				{
					encoder := pseudoEncoder
					value := &pseudoValue
					{{.SubField.GenInitEncoder}}
					_ = encoder
					_ = value
				}
			}
		}
	`))

	var g strErrBuf
	g.executeTemplate(templ, f)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a parsing context struct for a sequence field by delegating to its subfield, since the number of elements is unknown before parsing.
func (f *SequenceField) GenParsingContextStruct() (string, error) {
	// This is not a slice, because the number of elements is unknown before parsing.
	return f.SubField.GenParsingContextStruct()
}

// (AI GENERATED DESCRIPTION): Delegates the generation of initialization context to the underlying subfield’s GenInitContext method.
func (f *SequenceField) GenInitContext() (string, error) {
	return f.SubField.GenInitContext()
}

// (AI GENERATED DESCRIPTION): Generates Go code that encodes a SequenceField by iterating over each element and invoking the appropriate sub‑field encoding routine.
func (f *SequenceField) encodingGeneral(funcName string) (string, error) {
	templ := template.Must(template.New("SequenceEncodingGeneral").Parse(
		fmt.Sprintf(`if value.{{.Name}} != nil {
			for seq_i, seq_v := range value.{{.Name}} {
			pseudoEncoder := &encoder.{{.Name}}_subencoder[seq_i]
			pseudoValue := struct {
				{{.Name}} {{.FieldType}}
			}{
				{{.Name}}: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				{{.SubField.%s}}
				_ = encoder
				_ = value
			}
		}
	}
	`, funcName)))

	var g strErrBuf
	g.executeTemplate(templ, f)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates code that computes the encoding length of a Sequence field.
func (f *SequenceField) GenEncodingLength() (string, error) {
	return f.encodingGeneral("GenEncodingLength")
}

// (AI GENERATED DESCRIPTION): Generates a plan for encoding a SequenceField and returns the resulting string (or an error).
func (f *SequenceField) GenEncodingWirePlan() (string, error) {
	return f.encodingGeneral("GenEncodingWirePlan")
}

// (AI GENERATED DESCRIPTION): Encodes the SequenceField into its serialized string representation, returning the resulting encoding and any error.
func (f *SequenceField) GenEncodeInto() (string, error) {
	return f.encodingGeneral("GenEncodeInto")
}

// (AI GENERATED DESCRIPTION): Generates Go code that deserializes a sequence field by initializing the slice if nil, reading one element into a temporary struct, appending it to the slice, and decrementing the progress counter.
func (f *SequenceField) GenReadFrom() (string, error) {
	templ := template.Must(template.New("NameEncodeInto").Parse(`
		if value.{{.Name}} == nil {
			value.{{.Name}} = make([]{{.FieldType}}, 0)
		}
		{
			pseudoValue := struct {
				{{.Name}} {{.FieldType}}
			}{}
			{
				value := &pseudoValue
				{{.SubField.GenReadFrom}}
				_ = value
			}
			value.{{.Name}} = append(value.{{.Name}}, pseudoValue.{{.Name}})
		}
		progress --
	`))

	var g strErrBuf
	g.executeTemplate(templ, f)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a comment indicating that a sequence field is to be skipped during processing, ensuring it is not assigned a nil value.
func (f *SequenceField) GenSkipProcess() (string, error) {
	// Skip is called after all elements are parsed, so we should not assign nil.
	return "// sequence - skip", nil
}
