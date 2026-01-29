package codegen

import "fmt"

// TimeField represents a time field, recorded as milliseconds.
type TimeField struct {
	BaseTlvField

	opt bool
}

// (AI GENERATED DESCRIPTION): Creates a TimeField with the given name and type number, marking it optional when the annotation is `"optional"`.
func NewTimeField(name string, typeNum uint64, annotation string, _ *TlvModel) (TlvField, error) {
	return &TimeField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		opt: annotation == "optional",
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates Go source that computes the NDN wire‑encoding length of a TimeField, emitting the type‑number length plus the natural‑number length of the time value (in milliseconds) and handling optional fields with an `if` check.
func (f *TimeField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlne(GenTypeNumLen(f.TypeNum()))
		g.printlne(GenNaturalNumberLen("uint64(optval/time.Millisecond)", false))
		g.printlnf("}")
	} else {
		g.printlne(GenTypeNumLen(f.TypeNum()))
		g.printlne(GenNaturalNumberLen("uint64(value."+f.name+"/time.Millisecond)", false))
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the wire‑encoding plan for a time field by delegating to its encoding‑length generation logic.
func (f *TimeField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

// (AI GENERATED DESCRIPTION): Generates Go source code that encodes a TimeField into a packet by writing its type number and the time value (converted to milliseconds) as a natural number, and includes conditional logic for optional fields.
func (f *TimeField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	if f.opt {
		g.printlnf("if optval, ok := value.%s.Get(); ok {", f.name)
		g.printlne(GenEncodeTypeNum(f.typeNum))
		g.printlne(GenNaturalNumberEncode("uint64(optval/time.Millisecond)", false))
		g.printlnf("}")
	} else {
		g.printlne(GenEncodeTypeNum(f.typeNum))
		g.printlne(GenNaturalNumberEncode("uint64(value."+f.name+"/time.Millisecond)", false))
	}
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a code snippet that reads a natural‐number time value from a binary stream, interprets it as milliseconds, and assigns it to the struct’s time field (using a setter for optional fields).
func (f *TimeField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("{")
	g.printlnf("timeInt := uint64(0)")
	g.printlne(GenNaturalNumberDecode("timeInt"))
	if f.opt {
		g.printlnf("optval := time.Duration(timeInt) * time.Millisecond")
		g.printlnf("value.%s.Set(optval)", f.name)
	} else {
		g.printlnf("value.%s = time.Duration(timeInt) * time.Millisecond", f.name)
	}
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates code for skipping a TimeField during encoding: if optional it unsets the field, otherwise it assigns an ErrSkipRequired error.
func (f *TimeField) GenSkipProcess() (string, error) {
	if f.opt {
		return fmt.Sprintf("value.%s.Unset()", f.name), nil
	} else {
		return fmt.Sprintf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum), nil
	}
}
