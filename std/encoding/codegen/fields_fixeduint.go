package codegen

import (
	"fmt"
	"strings"
	"text/template"
)

// FixedUintField represents a fixed-length unsigned integer.
type FixedUintField struct {
	BaseTlvField

	opt      bool
	l        uint
	typeName string
}

func NewFixedUintField(name string, typeNum uint64, annotation string, _ *TlvModel) (TlvField, error) {
	if annotation == "" {
		return nil, ErrInvalidField
	}
	strs := strings.Split(annotation, ":")
	optional := false
	if len(strs) >= 2 && strs[1] == "optional" {
		optional = true
	}
	l := uint(0)
	switch strs[0] {
	case "byte":
		l = 1
	case "uint16":
		l = 2
	case "uint32":
		l = 4
	case "uint64":
		l = 8
	}
	return &FixedUintField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		opt:      optional,
		l:        l,
		typeName: strs[0],
	}, nil
}

func (f *FixedUintField) GenMainStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s %s", f.name, f.typeName)
	if f.opt {
		g.printlnf("_%s_valid bool", f.name)
	}
	return g.output()
}

func (f *FixedUintField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf_if(f.opt, "if value._%s_valid {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlnf("l += 1 + %d", f.l)
	g.printlnf_if(f.opt, "}")
	return g.output()
}

func (f *FixedUintField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

func (f *FixedUintField) GenEncodeInto() (string, error) {
	g := strErrBuf{}

	gen := func(name string) (string, error) {
		gi := strErrBuf{}
		switch f.l {
		case 1:
			gi.printlnf("buf[pos] = 1")
			gi.printlnf("buf[pos+1] = byte(%s)", name)
			gi.printlnf("pos += %d", 2)
		case 2:
			gi.printlnf("buf[pos] = 2")
			gi.printlnf("binary.BigEndian.PutUint16(buf[pos+1:], uint16(%s))", name)
			gi.printlnf("pos += %d", 3)
		case 4:
			gi.printlnf("buf[pos] = 4")
			gi.printlnf("binary.BigEndian.PutUint32(buf[pos+1:], uint32(%s))", name)
			gi.printlnf("pos += %d", 5)
		case 8:
			gi.printlnf("buf[pos] = 8")
			gi.printlnf("binary.BigEndian.PutUint64(buf[pos+1:], uint64(%s))", name)
			gi.printlnf("pos += %d", 9)
		}
		return gi.output()
	}

	g.printlnf_if(f.opt, "if value._%s_valid {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(gen("value." + f.name))
	g.printlnf_if(f.opt, "}")

	return g.output()
}

func (f *FixedUintField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	digit := ""
	switch f.l {
	case 1:
		digit = "byte"
	case 2:
		digit = "uint16"
	case 4:
		digit = "uint32"
	case 8:
		digit = "uint64"
	}

	gen := func(name string) {
		if f.l == 1 {
			g.printlnf("%s, err = reader.ReadByte()", name)
			g.printlnf("if err == io.EOF {")
			g.printlnf("err = io.ErrUnexpectedEOF")
			g.printlnf("}")
		} else {
			const Temp = `{{.Name}} = {{.Digit}}(0)
			{
				for i := 0; i < int(l); i++ {
					x := byte(0)
					x, err = reader.ReadByte()
					if err != nil {
						if err == io.EOF {
							err = io.ErrUnexpectedEOF
						}
						break
					}
					{{.Name}} = {{.Digit}}({{.Name}}<<8) | {{.Digit}}(x)
				}
			}
			`
			t := template.Must(template.New("FixedUintDecode").Parse(Temp))
			g.executeTemplate(t, struct {
				Name  string
				Digit string
			}{
				Name:  name,
				Digit: digit,
			})
		}
	}

	// if f.opt {
	// 	g.printlnf("{")

	// Special case for a single byte - directly use wire address
	// This is useful to modify the TLV in-place (e.g. HopLimit)
	// if f.l == 1 {
	// 	g.printlnf("err = reader.Skip(1)")
	// 	g.printlnf("if err == io.EOF {")
	// 	g.printlnf("err = io.ErrUnexpectedEOF")
	// 	g.printlnf("}")
	// 	g.printlnf("value.%s = &reader.Range(reader.Pos()-1, reader.Pos())[0][0]", f.name)
	// } else {
	// 	g.printlnf("tempVal := %s(0)", digit)
	// 	gen("tempVal")
	// 	g.printlnf("value.%s = &tempVal", f.name)
	// }

	// 	g.printlnf("}")
	// } else {

	gen("value." + f.name)
	g.printlnf_if(f.opt, "value._%s_valid = true", f.name)
	// }
	return g.output()
}

func (f *FixedUintField) GenSkipProcess() (string, error) {
	if f.opt {
		return fmt.Sprintf("value._%s_valid = false", f.name), nil
	} else {
		return fmt.Sprintf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum), nil
	}
}
