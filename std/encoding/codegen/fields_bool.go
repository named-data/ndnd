package codegen

import "fmt"

// BoolField represents a boolean field.
type BoolField struct {
	BaseTlvField
}

func NewBoolField(name string, typeNum uint64, _ string, _ *TlvModel) (TlvField, error) {
	return &BoolField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
	}, nil
}

func (f *BoolField) GenMainStruct() (string, error) {
	return fmt.Sprintf("%s bool", f.name), nil
}

func (f *BoolField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenTypeNumLen(0))
	g.printlnf("}")
	return g.output()
}

func (f *BoolField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

func (f *BoolField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenEncodeTypeNum(0))
	g.printlnf("}")
	return g.output()
}

func (f *BoolField) GenReadFrom() (string, error) {
	return "value." + f.name + " = true", nil
}

func (f *BoolField) GenSkipProcess() (string, error) {
	return "value." + f.name + " = false", nil
}
