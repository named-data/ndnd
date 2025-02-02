package codegen

import "fmt"

// TimeField represents a time field, recorded as milliseconds.
type TimeField struct {
	BaseTlvField

	opt bool
}

func NewTimeField(name string, typeNum uint64, annotation string, _ *TlvModel) (TlvField, error) {
	return &TimeField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		opt: annotation == "optional",
	}, nil
}

func (f *TimeField) GenMainStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s time.Duration", f.name)
	if f.opt {
		g.printlnf("_%s_valid bool", f.name)
	}
	return g.output()
}

func (f *TimeField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf_if(f.opt, "if value._%s_valid {", f.name)
	g.printlne(GenTypeNumLen(f.TypeNum()))
	g.printlne(GenNaturalNumberLen("uint64(value."+f.name+"/time.Millisecond)", false))
	g.printlnf_if(f.opt, "}")
	return g.output()
}

func (f *TimeField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

func (f *TimeField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf_if(f.opt, "if value._%s_valid {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenNaturalNumberEncode("uint64(value."+f.name+"/time.Millisecond)", false))
	g.printlnf_if(f.opt, "}")
	return g.output()
}

func (f *TimeField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("{")
	g.printlnf("timeInt := uint64(0)")
	g.printlne(GenNaturalNumberDecode("timeInt"))
	g.printlnf("value.%s = time.Duration(timeInt) * time.Millisecond", f.name)
	g.printlnf_if(f.opt, "value._%s_valid = true", f.name)
	g.printlnf("}")
	return g.output()
}

func (f *TimeField) GenSkipProcess() (string, error) {
	if f.opt {
		return fmt.Sprintf("value._%s_valid = false", f.name), nil
	} else {
		return fmt.Sprintf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum), nil
	}
}
