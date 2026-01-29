package codegen

import (
	"fmt"
)

// ByteField represents a pointer to the wire address of a byte.
type ByteField struct {
	BaseTlvField
}

// (AI GENERATED DESCRIPTION): Creates a ByteField initialized with the given name and type number, returning it as a TlvField.
func NewByteField(name string, typeNum uint64, annotation string, _ *TlvModel) (TlvField, error) {
	return &ByteField{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
	}, nil
}

// (AI GENERATED DESCRIPTION): Generates Go code that adds the length of a non‑nil byte field (including its type number and length header) to a running total when encoding a TLV message.
func (f *ByteField) GenEncodingLength() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenTypeNumLen(f.typeNum))
	g.printlnf("l += 2")
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the wire‑encoding plan for a byte field by delegating to its `GenEncodingLength` method.
func (f *ByteField) GenEncodingWirePlan() (string, error) {
	return f.GenEncodingLength()
}

// (AI GENERATED DESCRIPTION): Generates code that encodes an optional single‑byte field into a buffer, writing the field’s type number, a length byte of 1, and the byte value if the field is present.
func (f *ByteField) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	g.printlnf("if value.%s != nil {", f.name)
	g.printlne(GenEncodeTypeNum(f.typeNum))
	g.printlnf("buf[pos] = 1")
	g.printlnf("buf[pos+1] = byte(*value.%s)", f.name)
	g.printlnf("pos += 2")
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates code that reads a single byte from a reader, assigns it to the field, and converts an EOF into an unexpected‑EOF error.
func (f *ByteField) GenReadFrom() (string, error) {
	g := strErrBuf{}
	g.printlnf("{")
	g.printlnf("buf, err := reader.ReadBuf(1)")
	g.printlnf("if err == io.EOF {")
	g.printlnf("err = io.ErrUnexpectedEOF")
	g.printlnf("}")
	g.printlnf("value.%s = &buf[0]", f.name)
	g.printlnf("}")
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates Go code that assigns `nil` to the field when the field is skipped during decoding.
func (f *ByteField) GenSkipProcess() (string, error) {
	return fmt.Sprintf("value.%s = nil", f.name), nil
}
