package codegen

import "strings"

// ProcedureArgument is a variable used during encoding and decoding procedure.
type ProcedureArgument struct {
	BaseTlvField

	argType string
}

// (AI GENERATED DESCRIPTION): Generates a string representing a struct field by concatenating the argument’s name and type, returning it for use in an encoder struct definition.
func (f *ProcedureArgument) GenEncoderStruct() (string, error) {
	return f.name + " " + f.argType, nil
}

// (AI GENERATED DESCRIPTION): Generates a parsing‑context struct field declaration by concatenating the procedure argument’s name and type into a string.
func (f *ProcedureArgument) GenParsingContextStruct() (string, error) {
	return f.name + " " + f.argType, nil
}

// NewProcedureArgument creates a ProcedureArgument field.
func NewProcedureArgument(name string, _ uint64, annotation string, _ *TlvModel) (TlvField, error) {
	return &ProcedureArgument{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: 0,
		},
		argType: annotation,
	}, nil
}

// OffsetMarker is a marker that marks a position in the wire.
type OffsetMarker struct {
	BaseTlvField

	noCopy bool
}

// (AI GENERATED DESCRIPTION): Generates Go struct field declarations for an `OffsetMarker`, emitting a field for the value, an optional wire‑index field when `noCopy` is true, and a field for the marker’s position.
func (f *OffsetMarker) GenEncoderStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s int", f.name)
	if f.noCopy {
		g.printlnf("%s_wireIdx int", f.name)
	}
	g.printlnf("%s_pos int", f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a parsing context struct string for the offset marker by returning its name followed by the type `int`.
func (f *OffsetMarker) GenParsingContextStruct() (string, error) {
	return f.name + " " + "int", nil
}

// (AI GENERATED DESCRIPTION): Generates the code to read an `OffsetMarker` by delegating to its skip‑processing logic.
func (f *OffsetMarker) GenReadFrom() (string, error) {
	return f.GenSkipProcess()
}

// (AI GENERATED DESCRIPTION): Generates code that stores the current start position into the context variable named by `f.name`.
func (f *OffsetMarker) GenSkipProcess() (string, error) {
	return "context." + f.name + " = int(startPos)", nil
}

// (AI GENERATED DESCRIPTION): Generates a Go code snippet that assigns the current encoding length `l` to the encoder’s field named by `f.name` (e.g., `encoder.foo = int(l)`).
func (f *OffsetMarker) GenEncodingLength() (string, error) {
	return "encoder." + f.name + " = int(l)", nil
}

// (AI GENERATED DESCRIPTION): Generates code that writes the encoder’s current wire index (if `noCopy` is true) and position into the offset marker’s fields.
func (f *OffsetMarker) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	if f.noCopy {
		g.printlnf("encoder.%s_wireIdx = int(wireIdx)", f.name)
	}
	g.printlnf("encoder.%s_pos = int(pos)", f.name)
	return g.output()
}

// NewOffsetMarker creates an offset marker field.
func NewOffsetMarker(name string, _ uint64, _ string, model *TlvModel) (TlvField, error) {
	return &OffsetMarker{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: 0,
		},
		noCopy: model.NoCopy,
	}, nil
}

// RangeMarker is a marker that catches a range in the wire from an OffsetMarker to current position.
// It is necessary because the offset given by OffsetMarker is not necessarily from the beginning of the outmost TLV,
// when parsing. It is the same with OffsetMarker for encoding.
type RangeMarker struct {
	BaseTlvField

	noCopy     bool
	startPoint string
	sigCovered string
}

// (AI GENERATED DESCRIPTION): Generates the Go struct definition string for a RangeMarker encoder, including fields for the marker name, an optional wire index if `noCopy` is set, and a position index.
func (f *RangeMarker) GenEncoderStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s int", f.name)
	if f.noCopy {
		g.printlnf("%s_wireIdx int", f.name)
	}
	g.printlnf("%s_pos int", f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the code that assigns the encoder’s field (named by f.name) the value int(l).
func (f *RangeMarker) GenEncodingLength() (string, error) {
	return "encoder." + f.name + " = int(l)", nil
}

// (AI GENERATED DESCRIPTION): Generates Go code that updates the encoder’s position for a RangeMarker and, if `noCopy` is set, also assigns the current wire index.
func (f *RangeMarker) GenEncodeInto() (string, error) {
	g := strErrBuf{}
	if f.noCopy {
		g.printlnf("encoder.%s_wireIdx = int(wireIdx)", f.name)
	}
	g.printlnf("encoder.%s_pos = int(pos)", f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates a Go struct field definition for the range marker’s name, declaring it as an `int` field in the parsing context.
func (f *RangeMarker) GenParsingContextStruct() (string, error) {
	g := strErrBuf{}
	g.printlnf("%s int", f.name)
	return g.output()
}

// (AI GENERATED DESCRIPTION): Generates the read operation for a RangeMarker by delegating to GenSkipProcess, effectively producing a skip‑processing block.
func (f *RangeMarker) GenReadFrom() (string, error) {
	return f.GenSkipProcess()
}

// (AI GENERATED DESCRIPTION): Generates code that assigns the starting position to a context field and updates a signature‑covered range by calling `reader.Range` with that position.
func (f *RangeMarker) GenSkipProcess() (string, error) {
	g := strErrBuf{}
	g.printlnf("context.%s = int(startPos)", f.name)
	g.printlnf("context.%s = reader.Range(context.%s, startPos)", f.sigCovered, f.startPoint)
	return g.output()
}

// NewOffsetMarker creates an range marker field.
func NewRangeMarker(name string, typeNum uint64, annotation string, model *TlvModel) (TlvField, error) {
	strs := strings.Split(annotation, ":")
	if len(strs) < 2 || strs[0] == "" || strs[1] == "" {
		return nil, ErrInvalidField
	}
	return &RangeMarker{
		BaseTlvField: BaseTlvField{
			name:    name,
			typeNum: typeNum,
		},
		startPoint: strs[0],
		sigCovered: strs[1],
		noCopy:     model.NoCopy,
	}, nil
}
