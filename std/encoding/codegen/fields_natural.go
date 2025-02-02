package codegen

import "fmt"

// NaturalField represents a natural number field.
type NaturalField struct {
	BaseTlvField

	opt bool
}

func NewNaturalField(name string, typeNum uint64, annotation string, _ *TlvModel) (TlvField, error) {
	return &NaturalField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		opt: annotation == "optional",
	}, nil
}

func (f *NaturalField) GenMainStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s uint64", f.name)
	if f.opt {
		g.printlnf("_%s_valid bool", f.name)
	}
	return g.output()
}

func (f *NaturalField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf_if(f.opt, "if value._%s_valid {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen("value."+f.name, false))
	g.printlnf_if(f.opt, "}")
	return g.output()
}

func (f *NaturalField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

func (f *NaturalField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf_if(f.opt, "if value._%s_valid {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenNaturalNumberEncode("value."+f.name, false))
	g.printlnf_if(f.opt, "}")
	return g.output()
}

func (f *NaturalField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlne(GenNaturalNumberDecode("value." + f.name))
	g.printlnf_if(f.opt, "value._%s_valid = true", f.name)
	return g.output()
}

func (f *NaturalField) GenSkipProcess() (string, error) {
	if f.opt {
		return fmt.Sprintf("value._%s_valid = false", f.name), nil
	} else {
		return fmt.Sprintf("err = enc.ErrSkipRequired{Name: \"%s\", TypeNum: %d}", f.name, f.typeNum), nil
	}
}
