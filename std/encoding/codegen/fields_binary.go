package codegen

import "fmt"

// BinaryField represents a binary string field of type Buffer or []byte.
// BinaryField always makes a copy during encoding.
type BinaryField struct {
	BaseTlvField
}

// (AI GENERATED DESCRIPTION): Creates a BinaryField TLV instance with the specified name and type number.
func NewBinaryField(name string, typeNum uint64, _ string, _ *TlvModel) (TlvField, error) {
	return &BinaryField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
	}, nil
}

// (AI GENERATED DESCRIPTION): Computes the TLV‑encoded length of a binary field, adding the type number and length prefix bytes plus the field’s data length only when the field is non‑nil.
func (f *BinaryField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlne(GenNaturalNumberLen(fmt.Sprintf("len(value.%s)", f.name), true))
	g.printlnf("l += uint(len(value.%s))", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Returns the wire‑encoding plan for a binary field by delegating to GenEncodingLength.
func (f *BinaryField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

// (AI GENERATED DESCRIPTION): Generates Go code that encodes a non‑nil binary field into a buffer, writing its type number, length, and data payload.
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

// (AI GENERATED DESCRIPTION): Generates code that allocates a byte slice for the binary field and reads the full data from the reader into that slice.
func (f *BinaryField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("value.%s = make([]byte, l)", f.name)
	g.printlnf("_, err = reader.ReadFull(value.%s)", f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a statement that sets the BinaryField’s value to `nil` during skip processing.
func (f *BinaryField) GenSkipProcess() (string, error) {
	return "value." + f.name + " = nil", nil
}
