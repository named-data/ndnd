package codegen

import "fmt"

// BinaryField represents a binary string field of type Buffer or []byte.
// BinaryField always makes a copy during encoding.
type BinaryField struct {
	BaseTlvField
}

func NewBinaryField(name string, typeNum uint64, _ string, _ *TlvModel) (TlvField, error) {
	return &BinaryField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
	}, nil
}

func (f *BinaryField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen(fmt.Sprintf("len(value.%s)", f.name), true))
	g.printlnf("l += uint(len(value.%s))", f.name)
	g.printlnf("}")
	return g.output()
}

func (f *BinaryField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

func (f *BinaryField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlne(GenNaturalNumberEncode("len(value."+f.name+")", true))
	g.printlnf("copy(buf[pos:], value.%s)", f.name)
	g.printlnf("pos += uint(len(value.%s))", f.name)
	g.printlnf("}")
	return g.output()
}

func (f *BinaryField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("value.%s = make([]byte, l)", f.name)
	g.printlnf("_, err = reader.ReadFull(value.%s)", f.name)
	return g.output()
}

func (f *BinaryField) GenSkipProcess() (string, error) {
	return "value." + f.name + " = nil", nil
}
