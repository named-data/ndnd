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

func (f *SequenceField) GenMainStruct() (string, error) {
	return fmt.Sprintf("%s []%s", f.name, f.FieldType), nil
}

func (f *SequenceField) GenEncoderStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s_subencoder []struct{", f.name)
	g.printlne(f.SubField.GenEncoderStruct())
	g.printlnf("}")
	return g.output()
}

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

func (f *SequenceField) GenParsingContextStruct() (string, error) {
	// This is not a slice, because the number of elements is unknown before parsing.
	return f.SubField.GenParsingContextStruct()
}

func (f *SequenceField) GenInitContext() (string, error) {
	return f.SubField.GenInitContext()
}

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

func (f *SequenceField) GenEncodingLength() (string, error) {
	return f.encodingGeneral("GenEncodingLength")
}

func (f *SequenceField) GenEncodingWirePlan() (string, error) {
	return f.encodingGeneral("GenEncodingWirePlan")
}

func (f *SequenceField) GenEncodeInto() (string, error) {
	return f.encodingGeneral("GenEncodeInto")
}

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

func (f *SequenceField) GenSkipProcess() (string, error) {
	// Skip is called after all elements are parsed, so we should not assign nil.
	return "// sequence - skip", nil
}
