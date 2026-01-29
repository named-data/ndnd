package encoding

import (
	"fmt"
	"io"
)

// Buffer is a buffer of bytes
type Buffer []byte

// Wire is a collection of Buffer. May be allocated in non-contiguous memory.
type Wire []Buffer

// (AI GENERATED DESCRIPTION): Combines multiple byte slices in a `Wire` into one contiguous byte slice.
func (w Wire) Join() []byte {
	if len(w) == 0 {
		return []byte{}
	} else if len(w) == 1 {
		return w[0]
	}

	n := 0
	for _, v := range w {
		n += len(v)
	}

	b := make([]byte, n)
	bp := copy(b, w[0])
	for _, v := range w[1:] {
		bp += copy(b[bp:], v)
	}
	return b
}

// (AI GENERATED DESCRIPTION): Calculates and returns the cumulative byte length of all elements contained within the Wire.
func (w Wire) Length() uint64 {
	ret := uint64(0)
	for _, v := range w {
		ret += uint64(len(v))
	}
	return ret
}

type ErrFormat struct {
	Msg string
}

// (AI GENERATED DESCRIPTION): Returns the stored error message string of an ErrFormat error instance.
func (e ErrFormat) Error() string {
	return e.Msg
}

type ErrNotFound struct {
	Key string
}

// (AI GENERATED DESCRIPTION): Returns an error string indicating that the specified key was not found.
func (e ErrNotFound) Error() string {
	return e.Key + ": not found"
}

// ParseReader is an interface operating on Buffer and Wire
type ParseReader interface {
	io.Reader
	io.ByteScanner

	// ReadWire reads a list of buffers in place without copy.
	// It always tries to read the required length of bytes.
	ReadWire(l int) (Wire, error)

	// ReadBuf reads a continuous buffer, trying to avoid copy.
	ReadBuf(l int) (Buffer, error)

	// Range returns a wire that contains the bytes between start and end, without copy.
	Range(start, end int) Wire

	// Pos returns the current position in the buffer/wire.
	Pos() int

	// Length returns the length of the buffer/wire.
	Length() int

	// Skip skips the next n bytes.
	Skip(n int) error

	// Delegate returns a new ParseReader that starts from the current position with length l.
	// The result is equivalent to the following:
	//
	//   start := r.Pos()
	//   r.Skip(l)
	//   return r.Range(start, r.Pos())
	Delegate(l int) ParseReader
}

type ErrUnrecognizedField struct {
	TypeNum TLNum
}

// (AI GENERATED DESCRIPTION): Formats and returns an error message indicating that an unrecognized field with a critical type number exists, including that type number.
func (e ErrUnrecognizedField) Error() string {
	return fmt.Sprintf("There exists an unrecognized field that has a critical type number: %d", e.TypeNum)
}

var ErrBufferOverflow = fmt.Errorf("buffer overflow when parsing. One of the TLV Length is wrong")

var ErrIncorrectDigest = fmt.Errorf("the sha256 digest is missing or incorrect")

type ErrSkipRequired struct {
	Name    string
	TypeNum TLNum
}

// (AI GENERATED DESCRIPTION): Formats an error message indicating that a required field (identified by its name and type number) is missing from the input.
func (e ErrSkipRequired) Error() string {
	return fmt.Sprintf("The required field %s(%d) is missing in the input", e.Name, e.TypeNum)
}

type ErrFailToParse struct {
	TypeNum TLNum
	Err     error
}

// (AI GENERATED DESCRIPTION): Generates an error string indicating that parsing of a specific field failed, displaying the field’s type number and the underlying error.
func (e ErrFailToParse) Error() string {
	return fmt.Sprintf("Failed to parse field %d: %v", e.TypeNum, e.Err)
}

// (AI GENERATED DESCRIPTION): Unwrap returns the underlying error stored in the ErrFailToParse error wrapper.
func (e ErrFailToParse) Unwrap() error {
	return e.Err
}

type ErrUnexpected struct {
	Err error
}

// (AI GENERATED DESCRIPTION): Formats and returns a descriptive error string for an unexpected parsing error, prefixing the underlying error message.
func (e ErrUnexpected) Error() string {
	return fmt.Sprintf("Unexpected error happened in parsing: %v", e.Err)
}

// (AI GENERATED DESCRIPTION): Retrieves the underlying error wrapped by ErrUnexpected.
func (e ErrUnexpected) Unwrap() error {
	return e.Err
}

// PlaceHolder is an empty structure that used to give names of procedure arguments.
type PlaceHolder struct{}

type ErrIncompatibleType struct {
	Name    string
	ValType string
	TypeNum TLNum
	Value   any
}

// (AI GENERATED DESCRIPTION): Formats an error message for an incompatible field type, showing the field name, type number, expected type, and the actual value that caused the mismatch.
func (e ErrIncompatibleType) Error() string {
	return fmt.Sprintf("The field %s(%d) expected type %s but got %+v", e.Name, e.TypeNum, e.ValType, e.Value)
}
