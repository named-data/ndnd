package codegen

import (
	"bytes"
	"text/template"
)

// TlvModel represents a TLV encodable structure.
type TlvModel struct {
	Name string

	// PrivMethods indicates whether generated methods are private. False by default.
	// Enabled by `private` annotation.
	PrivMethods bool

	// NoCopy indicates whether to avoid copying []byte into wire. False by default.
	// Enabled by `nocopy` annotation.
	NoCopy bool

	// GenDict indicates whether to generate ToDict/FromDict for this model.
	GenDict bool

	// Ordered indicates whether fields require ordering. False by default.
	// Enabled by `ordered` annotation.
	Ordered bool

	// WithParsingContext is true if any field has a non-trivial GenParsingContextStruct()
	WithParsingContext bool

	// Fields are the TLV fields of the structure.
	Fields []TlvField
}

// (AI GENERATED DESCRIPTION): Sets the corresponding boolean configuration flags of a TlvModel based on the supplied option string, panicking if the option is unrecognized.
func (m *TlvModel) ProcessOption(option string) {
	switch option {
	case "private":
		m.PrivMethods = true
	case "nocopy":
		m.NoCopy = true
	case "dict":
		m.GenDict = true
	case "ordered":
		m.Ordered = true
	default:
		panic("unknown TlvModel option: " + option)
	}
}

// (AI GENERATED DESCRIPTION): Generates a Go struct definition that encodes a TLV model, including a length field, an optional wire plan slice, and nested encoder fields for each component.
func (m *TlvModel) GenEncoderStruct(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelEncoderStruct").Parse(`
		type {{.Name}}Encoder struct {
			Length uint
			{{if .NoCopy}}
				wirePlan []uint
			{{end}}
			{{- range $f := .Fields}}
				{{$f.GenEncoderStruct}}
			{{- end}}
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates the Init method for a TLV encoder, initializing each field, computing the total encoding length, and building a wire‑plan slice for models that do not copy payload data.
func (m *TlvModel) GenInitEncoder(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelInitEncoderStruct").Parse(`
		func (encoder *{{.Name}}Encoder) Init(value *{{.Name}}) {
			{{- range $f := .Fields}}
				{{$f.GenInitEncoder}}
			{{- end}}

			l := uint(0)
			{{- range $f := .Fields}}
				{{$f.GenEncodingLength}}
			{{- end}}
			encoder.Length = l

			{{if .NoCopy}}
				wirePlan := make([]uint, 0, 8)
				l = uint(0)
				{{- range $f := .Fields}}
					{{$f.GenEncodingWirePlan}}
				{{- end}}
				if l > 0 {
					wirePlan = append(wirePlan, l)
				}
				encoder.wirePlan = wirePlan
			{{- end}}
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates Go source that implements encoding a TLV model into its wire representation, writing the encoder methods into the supplied buffer.
func (m *TlvModel) GenEncodeInto(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelEncodeInto").Parse(`
		func (encoder *{{.Name}}Encoder) EncodeInto(value *{{.Name}},
			{{- if .NoCopy}}wire enc.Wire{{else}}buf []byte{{end}}) {

			{{if .NoCopy}}
				wireIdx := 0
				buf := wire[wireIdx]
			{{end}}

			pos := uint(0)
			{{ range $f := .Fields}}
				{{$f.GenEncodeInto}}
			{{- end}}
		}

		func (encoder *{{.Name}}Encoder) Encode(value *{{.Name}}) enc.Wire {
			{{if .NoCopy -}}
				total := uint(0)
				for _, l := range encoder.wirePlan {
					total += l
				}
				content := make([]byte, total)

				wire := make(enc.Wire, len(encoder.wirePlan))
				for i, l := range encoder.wirePlan {
					if l > 0 {
						wire[i] = content[:l]
						content = content[l:]
					}
				}
				encoder.EncodeInto(value, wire)
			{{else}}
				wire := make(enc.Wire, 1)
				wire[0] = make([]byte, encoder.Length)
				buf := wire[0]
				encoder.EncodeInto(value, buf)
			{{end}}
			return wire
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates a Go struct named `<ModelName>ParsingContext` containing field declarations derived from the model’s fields and writes the resulting code into the supplied buffer.
func (m *TlvModel) GenParsingContextStruct(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelParsingContextStruct").Parse(`
		type {{.Name}}ParsingContext struct {
			{{- range $f := .Fields}}
				{{$f.GenParsingContextStruct}}
			{{- end}}
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates the Init method for the model’s parsing context, writing code that initializes each field defined in the TLV model.
func (m *TlvModel) GenInitContext(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelInitContext").Parse(`
		func (context *{{.Name}}ParsingContext) Init() {
			{{- range $f := .Fields}}
				{{$f.GenInitContext}}
			{{- end}}
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates the Parse method for a TlvModel, producing Go code that reads a TLV‑encoded buffer into the model struct while respecting field ordering, critical‑field rules, and skipping unknown or unhandled tags.
func (m *TlvModel) GenReadFrom(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelParse").Parse(`
		{{if .Model.WithParsingContext -}}
			func (context *{{.Model.Name}}ParsingContext) Parse
		{{- else -}}
			func {{if .Model.PrivMethods -}}parse{{else}}Parse{{end}}{{.Model.Name}}
		{{- end -}}
		(reader enc.WireView, ignoreCritical bool) (*{{.Model.Name}}, error) {
			{{ range $i, $f := $.Model.Fields}}
			var handled_{{$f.Name}} bool = false
			{{- end}}

			progress := -1
			_ = progress

			value := &{{.Model.Name}}{}
			var err error
			var startPos int
			for {
				startPos = reader.Pos()
				if startPos >= reader.Length() {
					break
				}
				typ := enc.TLNum(0)
				l := enc.TLNum(0)
				{{call .GenTlvNumberDecode "typ"}}
				{{call .GenTlvNumberDecode "l"}}

				err = nil

				{{- if (eq $.Model.Ordered true)}}
				for handled := false; !handled && progress < {{len .Model.Fields}}; progress ++ {
				{{- else}}
				if handled := false; true {
				{{- end}}
					switch typ {
						{{- range $i, $f := $.Model.Fields}}
						{{- if (ne $f.TypeNum 0)}}
					case {{$f.TypeNum}}:
							{{- if (eq $.Model.Ordered true)}}
						if progress + 1 == {{$i}} {
							{{- else}}
						if true {
							{{- end}}
							handled = true
							handled_{{$f.Name}} = true
							{{$f.GenReadFrom}}
						}
						{{- end}}
						{{- end}}
					default:
						if !ignoreCritical && {{.IsCritical}} {
							return nil, enc.ErrUnrecognizedField{TypeNum: typ}
						}
						handled = true
						err = reader.Skip(int(l))
					}
					if err == nil && !handled {
						{{- if (eq $.Model.Ordered true)}}
						switch progress {
							{{- range $i, $f := .Model.Fields}}
						case {{$i}} - 1:
							handled_{{$f.Name}} = true
							{{$f.GenSkipProcess}}
							{{- end}}
						}
						{{- end}}
					}
					if err != nil {
						return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
					}
				}
			}

			startPos = reader.Pos()
			err = nil

			{{ range $i, $f := $.Model.Fields}}
			if !handled_{{$f.Name}} && err == nil {
				{{$f.GenSkipProcess}}
			}
			{{- end}}

			if err != nil {
				return nil, err
			}

			return value, nil
		}
	`)).Execute(buf, struct {
		Model              *TlvModel
		GenTlvNumberDecode func(string) (string, error)
		IsCritical         string
	}{
		Model:              m,
		GenTlvNumberDecode: GenTlvNumberDecode,
		IsCritical:         `((typ <= 31) || ((typ & 1) == 1))`,
	})
}

// func (m *TlvModel) detectParsingContext() {
// 	m.WithParsingContext = false
// 	for _, f := range m.Fields {
// 		str, _ := f.GenParsingContextStruct()
// 		if str != "" {
// 			m.WithParsingContext = true
// 		}
// 	}
// }

// (AI GENERATED DESCRIPTION): Generates the public `Encode()` and `Bytes()` methods for a TLV struct, enabling the struct to be marshalled into a wire format (`enc.Wire`) and converted to a raw byte slice.
func (m *TlvModel) genPublicEncode(buf *bytes.Buffer) error {
	return template.Must(template.New("PublicEncode").Parse(`
		func (value *{{.Name}}) Encode() enc.Wire {
			encoder := {{.Name}}Encoder{}
			encoder.Init(value)
			return encoder.Encode(value)
		}

		func (value *{{.Name}}) Bytes() []byte {
			return value.Encode().Join()
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates a public Parse\<Type\> function that parses a serialized object of the given type from a WireView, initializing and invoking the corresponding parsing context.
func (m *TlvModel) genPublicParse(buf *bytes.Buffer) error {
	return template.Must(template.New("PublicParse").Parse(`
		func Parse{{.Name}}(reader enc.WireView, ignoreCritical bool) (*{{.Name}}, error) {
			context := {{.Name}}ParsingContext{}
			context.Init()
			return context.Parse(reader, ignoreCritical)
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates Go source code for a TLV model, emitting encoder structs, optional parsing context, initialization, encode/decode logic, public API helpers, and dictionary conversion routines.
func (m *TlvModel) Generate(buf *bytes.Buffer) error {
	// m.detectParsingContext()
	m.WithParsingContext = true
	err := m.GenEncoderStruct(buf)
	if err != nil {
		return err
	}
	buf.WriteRune('\n')
	if m.WithParsingContext {
		err = m.GenParsingContextStruct(buf)
		if err != nil {
			return err
		}
		buf.WriteRune('\n')
	}
	err = m.GenInitEncoder(buf)
	if err != nil {
		return err
	}
	buf.WriteRune('\n')
	if m.WithParsingContext {
		err = m.GenInitContext(buf)
		if err != nil {
			return err
		}
		buf.WriteRune('\n')
	}
	err = m.GenEncodeInto(buf)
	if err != nil {
		return err
	}
	buf.WriteRune('\n')
	err = m.GenReadFrom(buf)
	if err != nil {
		return err
	}
	buf.WriteRune('\n')
	if !m.PrivMethods {
		err = m.genPublicEncode(buf)
		if err != nil {
			return err
		}
		buf.WriteRune('\n')
		if m.WithParsingContext {
			err = m.genPublicParse(buf)
			if err != nil {
				return err
			}
			buf.WriteRune('\n')
		}
	}
	if m.GenDict {
		err = m.GenToDict(buf)
		if err != nil {
			return err
		}
		buf.WriteRune('\n')
		err = m.GenFromDict(buf)
		if err != nil {
			return err
		}
		buf.WriteRune('\n')
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Generates a `ToDict` method that serializes a model instance into a `map[string]any` by converting each field to a dictionary entry.
func (m *TlvModel) GenToDict(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelToDict").Parse(`
		func (value *{{.Name}}) ToDict() map[string]any {
			dict := map[string]any{}
			{{- range $f := .Fields}}
			{{$f.GenToDict}}
			{{- end}}
			return dict
		}
	`)).Execute(buf, m)
}

// (AI GENERATED DESCRIPTION): Generates Go source that defines a `DictTo<StructName>` function, converting a `map[string]any` into a typed struct by applying each field’s custom parsing logic.
func (m *TlvModel) GenFromDict(buf *bytes.Buffer) error {
	return template.Must(template.New("ModelFromDict").Parse(`
		func DictTo{{.Name}}(dict map[string]any) (*{{.Name}}, error) {
			value := &{{.Name}}{}
			var err error = nil
			{{- range $f := .Fields}}
			{{$f.GenFromDict}}
			if err != nil {
				return nil, err
			}
			{{- end}}
			return value, nil
		}
	`)).Execute(buf, m)
}
