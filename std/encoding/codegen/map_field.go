package codegen

import (
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

type MapField struct {
	BaseTlvField

	KeyField     TlvField
	ValField     TlvField
	KeyFieldType string
	ValFieldType string
}

// (AI GENERATED DESCRIPTION): Generates a Go source snippet that defines an encoder map for a MapField, mapping each key to a pointer to a nested struct that encodes the field’s value.
func (f *MapField) GenEncoderStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s_valencoder map[%s]*struct{", f.name, f.KeyFieldType)
	// KeyField can only be Natural or String, which do not need an encoder
	g.printlne(f.ValField.GenEncoderStruct())
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go source code that initializes an encoder for a map field, allocating a map of per‑value encoders and invoking the value field’s initialization logic for each entry.
func (f *MapField) GenInitEncoder() (string, error) {
	// SA Sequence Field
	// KeyField does not need an encoder
	templ := template.Must(template.New("MapInitEncoder").Parse(`{
		{{.Name}}_l := len(value.{{.Name}})
		encoder.{{.Name}}_valencoder = make(map[{{.KeyFieldType}}]*struct{
			{{.ValField.GenEncoderStruct}}
		}, {{.Name}}_l)
		for map_k := range value.{{.Name}} {
			pseudoEncoder := &struct{
				{{.ValField.GenEncoderStruct}}
			}{}
			encoder.{{.Name}}_valencoder[map_k] = pseudoEncoder
			pseudoValue := struct {
				{{.Name}}_v {{.ValFieldType}}
			}{
				{{.Name}}_v: value.{{.Name}}[map_k],
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				{{.ValField.GenInitEncoder}}
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

// (AI GENERATED DESCRIPTION): Generates a parsing‑context struct for a map field by delegating to its value field, since the map’s size is unknown until parsing.
func (f *MapField) GenParsingContextStruct() (string, error) {
	// This is not a slice, because the number of elements is unknown before parsing.
	return f.ValField.GenParsingContextStruct()
}

// (AI GENERATED DESCRIPTION): Delegates the generation of initialization context to the MapField's value field.
func (f *MapField) GenInitContext() (string, error) {
	return f.ValField.GenInitContext()
}

// (AI GENERATED DESCRIPTION): Generates the Go source that encodes a map field by iterating over each key‑value pair, selecting the appropriate encoder for the key, and invoking the specified encoding routine for both the key and the value.
func (f *MapField) encodingGeneral(funcName string) (string, error) {
	templ := template.Must(template.New("MapEncodingGeneral").Parse(fmt.Sprintf(`
		if value.{{.Name}} != nil {
				for map_k, map_v := range value.{{.Name}} {
				pseudoEncoder := encoder.{{.Name}}_valencoder[map_k]
				pseudoValue := struct {
					{{.Name}}_k {{.KeyFieldType}}
					{{.Name}}_v {{.ValFieldType}}
				}{
					{{.Name}}_k: map_k,
					{{.Name}}_v: map_v,
				}
				{
					encoder := pseudoEncoder
					value := &pseudoValue
					{{.KeyField.%[1]s}}
					{{.ValField.%[1]s}}
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

// (AI GENERATED DESCRIPTION): Generates the Go code that computes the encoding length of a MapField.
func (f *MapField) GenEncodingLength() (string, error) {
	return f.encodingGeneral("GenEncodingLength")
}

// (AI GENERATED DESCRIPTION): Generates an encoding‑wire plan string for a map field by delegating to the generic encoding routine.
func (f *MapField) GenEncodingWirePlan() (string, error) {
	return f.encodingGeneral("GenEncodingWirePlan")
}

// (AI GENERATED DESCRIPTION): Generates an encoded string representation of the MapField by delegating to its general encoding routine.
func (f *MapField) GenEncodeInto() (string, error) {
	return f.encodingGeneral("GenEncodeInto")
}

// (AI GENERATED DESCRIPTION): Generates code that reads a TLV‑encoded map field, initializing the map and inserting each decoded key/value pair into it.
func (f *MapField) GenReadFrom() (string, error) {
	templ := template.Must(template.New("NameEncodeInto").Parse(`
		if value.{{.M.Name}} == nil {
			value.{{.M.Name}} = make(map[{{.M.KeyFieldType}}]{{.M.ValFieldType}})
		}
		{
			pseudoValue := struct {
				{{.M.Name}}_k {{.M.KeyFieldType}}
				{{.M.Name}}_v {{.M.ValFieldType}}
			}{}
			{
				value := &pseudoValue
				{{.M.KeyField.GenReadFrom}}
				typ := enc.TLNum(0)
				l := enc.TLNum(0)
				{{call .GenTlvNumberDecode "typ"}}
				{{call .GenTlvNumberDecode "l"}}
				if typ != {{.M.ValField.TypeNum}} {
					return nil, enc.ErrFailToParse{TypeNum: {{.M.KeyField.TypeNum}}, Err: enc.ErrUnrecognizedField{TypeNum: typ}}
				}
				{{.M.ValField.GenReadFrom}}
				_ = value
			}
			value.{{.M.Name}}[pseudoValue.{{.M.Name}}_k] = pseudoValue.{{.M.Name}}_v
		}
		progress --
	`))

	var g strErrBuf
	g.executeTemplate(templ, struct {
		M                  *MapField
		GenTlvNumberDecode func(string) (string, error)
	}{
		M:                  f,
		GenTlvNumberDecode: GenTlvNumberDecode,
	})
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a placeholder comment for skipping map field processing after parsing, ensuring that no nil assignment occurs.
func (f *MapField) GenSkipProcess() (string, error) {
	// Skip is called after all elements are parsed, so we should not assign nil.
	return "// map - skip", nil
}

// (AI GENERATED DESCRIPTION): Generates a dictionary‑formatted string representation of the MapField’s contents.
func (f *MapField) GenToDict() (string, error) {
	return "ERROR = \"Unimplemented yet!\"", nil
}

// (AI GENERATED DESCRIPTION): Generates Go code for a `MapField` from a dictionary input (currently unimplemented).
func (f *MapField) GenFromDict() (string, error) {
	return "ERROR = \"Unimplemented yet!\"", nil
}

// (AI GENERATED DESCRIPTION): Creates a MapField TLV element by parsing the annotation to generate the corresponding key and value subfields.
func NewMapField(name string, typeNum uint64, annotation string, model *TlvModel) (TlvField, error) {
	strs := strings.SplitN(annotation, ":", 6)
	if len(strs) < 5 {
		return nil, ErrInvalidField
	}
	keyFieldType := strs[0]
	keyFieldClass := strs[1]
	valFieldTypeNum, err := strconv.ParseUint(strs[2], 0, 0)
	if err != nil {
		return nil, err
	}
	valFieldType := strs[3]
	valFieldClass := strs[4]
	if len(strs) >= 6 {
		annotation = strs[5]
	} else {
		annotation = ""
	}
	valField, err := CreateField(valFieldClass, name+"_v", valFieldTypeNum, annotation, model)
	if err != nil {
		return nil, err
	}
	keyField, err := CreateField(keyFieldClass, name+"_k", typeNum, annotation, model)
	if err != nil {
		return nil, err
	}
	return &MapField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		KeyField:     keyField,
		KeyFieldType: keyFieldType,
		ValField:     valField,
		ValFieldType: valFieldType,
	}, nil
}
