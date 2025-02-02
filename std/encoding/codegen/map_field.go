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

func (f *MapField) GenEncoderStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s_valencoder map[%s]*struct{", f.name, f.KeyFieldType)
	// KeyField can only be Natural or String, which do not need an encoder
	g.printlne(f.ValField.GenEncoderStruct())
	g.printlnf("}")
	return g.output()
}

func (f *MapField) GenMainStruct() (string, error) {
	return fmt.Sprintf("%s TODO", f.name), nil
}

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

func (f *MapField) GenParsingContextStruct() (string, error) {
	// This is not a slice, because the number of elements is unknown before parsing.
	return f.ValField.GenParsingContextStruct()
}

func (f *MapField) GenInitContext() (string, error) {
	return f.ValField.GenInitContext()
}

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

func (f *MapField) GenEncodingLength() (string, error) {
	return f.encodingGeneral("GenEncodingLength")
}

func (f *MapField) GenEncodingWirePlan() (string, error) {
	return f.encodingGeneral("GenEncodingWirePlan")
}

func (f *MapField) GenEncodeInto() (string, error) {
	return f.encodingGeneral("GenEncodeInto")
}

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

func (f *MapField) GenSkipProcess() (string, error) {
	// Skip is called after all elements are parsed, so we should not assign nil.
	return "// map - skip", nil
}

func (f *MapField) GenToDict() (string, error) {
	return "ERROR = \"Unimplemented yet!\"", nil
}

func (f *MapField) GenFromDict() (string, error) {
	return "ERROR = \"Unimplemented yet!\"", nil
}

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
