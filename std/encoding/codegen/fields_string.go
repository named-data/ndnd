package codegen

import "fmt"

// StringField represents a UTF-8 encoded string.
type StringField struct {
	BaseTlvField

	opt bool
}

// (AI GENERATED DESCRIPTION): Creates a new `StringField` TlvField with the given name and type number, and marks it optional if the annotation equals `"optional"`.
func NewStringField(name string, typeNum uint64, annotation string, _ *TlvModel) (TlvField, error) {
	return &StringField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		opt: annotation == "optional",
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates code that calculates the encoded length of a string field, adding its type tag, length prefix, and the string bytes, and handling optional fields by checking for presence before including them.
func (f *StringField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlne(GenTypeNumLen(f.typeNum))
		g.printlne(GenNaturalNumberLen("len(optval)", true))
		g.printlnf("l += uint(len(optval))")
		g.printlnf("}")
	} else {
		g.printlne(GenTypeNumLen(f.typeNum))
		g.printlne(GenNaturalNumberLen("len(value."+f.name+")", true))
		g.printlnf("l += uint(len(value.%s))", f.name)
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the wire‑encoding plan for a string field by returning its encoding‑length representation.
func (f *StringField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

// (AI GENERATED DESCRIPTION): Generates Go code that encodes a string field into a buffer by writing its type number, length, and byte data, handling optional values if present.
func (f *StringField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlne(GenEncodeTypeNum(f.typeNum))
		g.printlne(GenNaturalNumberEncode("len(optval)", true))
		g.printlnf("copy(buf[pos:], optval)")
		g.printlnf("pos += uint(len(optval))")
		g.printlnf("}")
	} else {
		g.printlne(GenEncodeTypeNum(f.typeNum))
		g.printlne(GenNaturalNumberEncode("len(value."+f.name+")", true))
		g.printlnf("copy(buf[pos:], value.%s)", f.name)
		g.printlnf("pos += uint(len(value.%s))", f.name)
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go source that reads a string of length `l` from a reader and assigns it to the field (using `Set` for optional fields).
func (f *StringField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("{")
	g.printlnf("var builder strings.Builder")
	g.printlnf("_, err = reader.CopyN(&builder, int(l))")
	g.printlnf("if err == nil {")
	if f.opt {
		g.printlnf("value.%s.Set(builder.String())", f.name)
	} else {
		g.printlnf("value.%s = builder.String()", f.name)
	}
	g.printlnf("}")
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the code snippet that either unsets an optional string field or produces a skip‑required error when a required string field is omitted.
func (f *StringField) GenSkipProcess() (string, error) {
	if f.opt {
		return fmt.Sprintf("value.%s.Unset()", f.name), nil
	} else {
		return fmt.Sprintf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum), nil
	}
}
