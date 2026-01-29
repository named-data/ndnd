package codegen

import "fmt"

// NaturalField represents a natural number field.
type NaturalField struct {
	BaseTlvField

	opt bool
}

// (AI GENERATED DESCRIPTION): Creates a NaturalField TLV descriptor with the given name and type number, marking it as optional when the annotation string equals "optional".
func NewNaturalField(name string, typeNum uint64, annotation string, _ *TlvModel) (TlvField, error) {
	return &NaturalField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		opt: annotation == "optional",
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates Go code that computes the encoding length of a NaturalField, handling optional values by wrapping the length calculation in an `if` check.
func (f *NaturalField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlne(GenTypeNumLen(f.typeNum))
		g.printlne(GenNaturalNumberLen("optval", false))
		g.printlnf("}")
	} else {
		g.printlne(GenTypeNumLen(f.typeNum))
		g.printlne(GenNaturalNumberLen("value."+f.name, false))
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the encoding wire plan for a NaturalField by delegating to its GenEncodingLength method.
func (f *NaturalField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

// (AI GENERATED DESCRIPTION): Generates Go source that writes the natural field’s type number and value into an encoding buffer, including an optional presence check when the field is marked optional.
func (f *NaturalField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlne(GenEncodeTypeNum(f.typeNum))
		g.printlne(GenNaturalNumberEncode("optval", false))
		g.printlnf("}")
	} else {
		g.printlne(GenEncodeTypeNum(f.typeNum))
		g.printlne(GenNaturalNumberEncode("value."+f.name, false))
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that reads a natural‑number field from a buffer, decoding it into a temporary variable and setting the field when optional, or decoding directly into the field when mandatory.
func (f *NaturalField) GenReadFrom() (string, error) {
	if f.opt {
		g := strErrBuf{}
		g.printlnf("{")
		g.printlnf("optval := uint64(0)")
		g.printlne(GenNaturalNumberDecode("optval"))
		g.printlnf("value.%s.Set(optval)", f.name)
		g.printlnf("}")
		return g.output()
	} else {
		return GenNaturalNumberDecode("value." + f.name)
	}
}

// (AI GENERATED DESCRIPTION): Generates code to handle skipping a field during encoding: if the field is optional it emits code to unset it, otherwise it produces an error indicating a required field was skipped.
func (f *NaturalField) GenSkipProcess() (string, error) {
	if f.opt {
		return fmt.Sprintf("value.%s.Unset()", f.name), nil
	} else {
		return fmt.Sprintf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum), nil
	}
}
