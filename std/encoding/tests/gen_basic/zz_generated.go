// Code generated by ndn tlv codegen DO NOT EDIT.
package gen_basic

import (
	"encoding/binary"
	"io"
	"strings"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
)

type FakeMetaInfoEncoder struct {
	length uint
}

type FakeMetaInfoParsingContext struct {
}

func (encoder *FakeMetaInfoEncoder) Init(value *FakeMetaInfo) {

	l := uint(0)
	l += 1
	switch x := value.Number; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}
	l += 1
	switch x := uint64(value.Time / time.Millisecond); {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}
	if value.Binary != nil {
		l += 1
		switch x := len(value.Binary); {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += uint(len(value.Binary))
	}
	encoder.length = l

}

func (context *FakeMetaInfoParsingContext) Init() {

}

func (encoder *FakeMetaInfoEncoder) EncodeInto(value *FakeMetaInfo, buf []byte) {

	pos := uint(0)

	buf[pos] = byte(24)
	pos += 1
	switch x := value.Number; {
	case x <= 0xff:
		buf[pos] = 1
		buf[pos+1] = byte(x)
		pos += 2
	case x <= 0xffff:
		buf[pos] = 2
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
		pos += 3
	case x <= 0xffffffff:
		buf[pos] = 4
		binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
		pos += 5
	default:
		buf[pos] = 8
		binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
		pos += 9
	}
	buf[pos] = byte(25)
	pos += 1
	switch x := uint64(value.Time / time.Millisecond); {
	case x <= 0xff:
		buf[pos] = 1
		buf[pos+1] = byte(x)
		pos += 2
	case x <= 0xffff:
		buf[pos] = 2
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
		pos += 3
	case x <= 0xffffffff:
		buf[pos] = 4
		binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
		pos += 5
	default:
		buf[pos] = 8
		binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
		pos += 9
	}
	if value.Binary != nil {
		buf[pos] = byte(26)
		pos += 1
		switch x := len(value.Binary); {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		copy(buf[pos:], value.Binary)
		pos += uint(len(value.Binary))
	}
}

func (encoder *FakeMetaInfoEncoder) Encode(value *FakeMetaInfo) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *FakeMetaInfoParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*FakeMetaInfo, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Number bool = false
	var handled_Time bool = false
	var handled_Binary bool = false

	progress := -1
	_ = progress

	value := &FakeMetaInfo{}
	var err error
	var startPos int
	for {
		startPos = reader.Pos()
		if startPos >= reader.Length() {
			break
		}
		typ := enc.TLNum(0)
		l := enc.TLNum(0)
		typ, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		if handled := false; true {
			switch typ {
			case 24:
				if true {
					handled = true
					handled_Number = true
					value.Number = uint64(0)
					{
						for i := 0; i < int(l); i++ {
							x := byte(0)
							x, err = reader.ReadByte()
							if err != nil {
								if err == io.EOF {
									err = io.ErrUnexpectedEOF
								}
								break
							}
							value.Number = uint64(value.Number<<8) | uint64(x)
						}
					}
				}
			case 25:
				if true {
					handled = true
					handled_Time = true
					{
						timeInt := uint64(0)
						timeInt = uint64(0)
						{
							for i := 0; i < int(l); i++ {
								x := byte(0)
								x, err = reader.ReadByte()
								if err != nil {
									if err == io.EOF {
										err = io.ErrUnexpectedEOF
									}
									break
								}
								timeInt = uint64(timeInt<<8) | uint64(x)
							}
						}
						value.Time = time.Duration(timeInt) * time.Millisecond
					}
				}
			case 26:
				if true {
					handled = true
					handled_Binary = true
					value.Binary = make([]byte, l)
					_, err = io.ReadFull(reader, value.Binary)
				}
			default:
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				handled = true
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_Number && err == nil {
		err = enc.ErrSkipRequired{Name: "Number", TypeNum: 24}
	}
	if !handled_Time && err == nil {
		err = enc.ErrSkipRequired{Name: "Time", TypeNum: 25}
	}
	if !handled_Binary && err == nil {
		value.Binary = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *FakeMetaInfo) Encode() enc.Wire {
	encoder := FakeMetaInfoEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *FakeMetaInfo) Bytes() []byte {
	return value.Encode().Join()
}

func ParseFakeMetaInfo(reader enc.ParseReader, ignoreCritical bool) (*FakeMetaInfo, error) {
	context := FakeMetaInfoParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type OptFieldEncoder struct {
	length uint
}

type OptFieldParsingContext struct {
}

func (encoder *OptFieldEncoder) Init(value *OptField) {

	l := uint(0)
	if value.Number != nil {
		l += 1
		switch x := *value.Number; {
		case x <= 0xff:
			l += 2
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
	}
	if value.Time != nil {
		l += 1
		switch x := uint64(*value.Time / time.Millisecond); {
		case x <= 0xff:
			l += 2
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
	}
	if value.Binary != nil {
		l += 1
		switch x := len(value.Binary); {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += uint(len(value.Binary))
	}
	if value.Bool {
		l += 1
		l += 1
	}
	encoder.length = l

}

func (context *OptFieldParsingContext) Init() {

}

func (encoder *OptFieldEncoder) EncodeInto(value *OptField, buf []byte) {

	pos := uint(0)

	if value.Number != nil {
		buf[pos] = byte(24)
		pos += 1
		switch x := *value.Number; {
		case x <= 0xff:
			buf[pos] = 1
			buf[pos+1] = byte(x)
			pos += 2
		case x <= 0xffff:
			buf[pos] = 2
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 4
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 8
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
	}
	if value.Time != nil {
		buf[pos] = byte(25)
		pos += 1
		switch x := uint64(*value.Time / time.Millisecond); {
		case x <= 0xff:
			buf[pos] = 1
			buf[pos+1] = byte(x)
			pos += 2
		case x <= 0xffff:
			buf[pos] = 2
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 4
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 8
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
	}
	if value.Binary != nil {
		buf[pos] = byte(26)
		pos += 1
		switch x := len(value.Binary); {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		copy(buf[pos:], value.Binary)
		pos += uint(len(value.Binary))
	}
	if value.Bool {
		buf[pos] = byte(48)
		pos += 1
		buf[pos] = byte(0)
		pos += 1
	}
}

func (encoder *OptFieldEncoder) Encode(value *OptField) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *OptFieldParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*OptField, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Number bool = false
	var handled_Time bool = false
	var handled_Binary bool = false
	var handled_Bool bool = false

	progress := -1
	_ = progress

	value := &OptField{}
	var err error
	var startPos int
	for {
		startPos = reader.Pos()
		if startPos >= reader.Length() {
			break
		}
		typ := enc.TLNum(0)
		l := enc.TLNum(0)
		typ, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		if handled := false; true {
			switch typ {
			case 24:
				if true {
					handled = true
					handled_Number = true
					{
						tempVal := uint64(0)
						tempVal = uint64(0)
						{
							for i := 0; i < int(l); i++ {
								x := byte(0)
								x, err = reader.ReadByte()
								if err != nil {
									if err == io.EOF {
										err = io.ErrUnexpectedEOF
									}
									break
								}
								tempVal = uint64(tempVal<<8) | uint64(x)
							}
						}
						value.Number = &tempVal
					}
				}
			case 25:
				if true {
					handled = true
					handled_Time = true
					{
						timeInt := uint64(0)
						timeInt = uint64(0)
						{
							for i := 0; i < int(l); i++ {
								x := byte(0)
								x, err = reader.ReadByte()
								if err != nil {
									if err == io.EOF {
										err = io.ErrUnexpectedEOF
									}
									break
								}
								timeInt = uint64(timeInt<<8) | uint64(x)
							}
						}
						tempVal := time.Duration(timeInt) * time.Millisecond
						value.Time = &tempVal
					}
				}
			case 26:
				if true {
					handled = true
					handled_Binary = true
					value.Binary = make([]byte, l)
					_, err = io.ReadFull(reader, value.Binary)
				}
			case 48:
				if true {
					handled = true
					handled_Bool = true
					value.Bool = true
				}
			default:
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				handled = true
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_Number && err == nil {
		value.Number = nil
	}
	if !handled_Time && err == nil {
		value.Time = nil
	}
	if !handled_Binary && err == nil {
		value.Binary = nil
	}
	if !handled_Bool && err == nil {
		value.Bool = false
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *OptField) Encode() enc.Wire {
	encoder := OptFieldEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *OptField) Bytes() []byte {
	return value.Encode().Join()
}

func ParseOptField(reader enc.ParseReader, ignoreCritical bool) (*OptField, error) {
	context := OptFieldParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type WireNameFieldEncoder struct {
	length uint

	Wire_length uint
	Name_length uint
}

type WireNameFieldParsingContext struct {
}

func (encoder *WireNameFieldEncoder) Init(value *WireNameField) {
	if value.Wire != nil {
		encoder.Wire_length = 0
		for _, c := range value.Wire {
			encoder.Wire_length += uint(len(c))
		}
	}
	if value.Name != nil {
		encoder.Name_length = 0
		for _, c := range value.Name {
			encoder.Name_length += uint(c.EncodingLength())
		}
	}

	l := uint(0)
	if value.Wire != nil {
		l += 1
		switch x := encoder.Wire_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Wire_length
	}
	if value.Name != nil {
		l += 1
		switch x := encoder.Name_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Name_length
	}
	encoder.length = l

}

func (context *WireNameFieldParsingContext) Init() {

}

func (encoder *WireNameFieldEncoder) EncodeInto(value *WireNameField, buf []byte) {

	pos := uint(0)

	if value.Wire != nil {
		buf[pos] = byte(1)
		pos += 1
		switch x := encoder.Wire_length; {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		for _, w := range value.Wire {
			copy(buf[pos:], w)
			pos += uint(len(w))
		}
	}
	if value.Name != nil {
		buf[pos] = byte(2)
		pos += 1
		switch x := encoder.Name_length; {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		for _, c := range value.Name {
			pos += uint(c.EncodeInto(buf[pos:]))
		}
	}
}

func (encoder *WireNameFieldEncoder) Encode(value *WireNameField) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *WireNameFieldParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*WireNameField, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Wire bool = false
	var handled_Name bool = false

	progress := -1
	_ = progress

	value := &WireNameField{}
	var err error
	var startPos int
	for {
		startPos = reader.Pos()
		if startPos >= reader.Length() {
			break
		}
		typ := enc.TLNum(0)
		l := enc.TLNum(0)
		typ, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		if handled := false; true {
			switch typ {
			case 1:
				if true {
					handled = true
					handled_Wire = true
					value.Wire, err = reader.ReadWire(int(l))
				}
			case 2:
				if true {
					handled = true
					handled_Name = true
					value.Name = make(enc.Name, l/2+1)
					startName := reader.Pos()
					endName := startName + int(l)
					for j := range value.Name {
						if reader.Pos() >= endName {
							value.Name = value.Name[:j]
							break
						}
						var err1, err3 error
						value.Name[j].Typ, err1 = enc.ReadTLNum(reader)
						l, err2 := enc.ReadTLNum(reader)
						value.Name[j].Val, err3 = reader.ReadBuf(int(l))
						if err1 != nil || err2 != nil || err3 != nil {
							err = io.ErrUnexpectedEOF
							break
						}
					}
					if err == nil && reader.Pos() != endName {
						err = enc.ErrBufferOverflow
					}
				}
			default:
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				handled = true
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_Wire && err == nil {
		value.Wire = nil
	}
	if !handled_Name && err == nil {
		value.Name = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *WireNameField) Encode() enc.Wire {
	encoder := WireNameFieldEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *WireNameField) Bytes() []byte {
	return value.Encode().Join()
}

func ParseWireNameField(reader enc.ParseReader, ignoreCritical bool) (*WireNameField, error) {
	context := WireNameFieldParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type MarkersEncoder struct {
	length uint

	startMarker     int
	startMarker_pos int
	Wire_length     uint
	argument        int
	Name_length     uint
	endMarker       int
	endMarker_pos   int
}

type MarkersParsingContext struct {
	startMarker int

	argument int

	endMarker int
}

func (encoder *MarkersEncoder) Init(value *Markers) {

	if value.Wire != nil {
		encoder.Wire_length = 0
		for _, c := range value.Wire {
			encoder.Wire_length += uint(len(c))
		}
	}

	if value.Name != nil {
		encoder.Name_length = 0
		for _, c := range value.Name {
			encoder.Name_length += uint(c.EncodingLength())
		}
	}

	l := uint(0)
	encoder.startMarker = int(l)
	if value.Wire != nil {
		l += 1
		switch x := encoder.Wire_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Wire_length
	}

	if value.Name != nil {
		l += 1
		switch x := encoder.Name_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Name_length
	}
	encoder.endMarker = int(l)
	encoder.length = l

}

func (context *MarkersParsingContext) Init() {

}

func (encoder *MarkersEncoder) EncodeInto(value *Markers, buf []byte) {

	pos := uint(0)

	encoder.startMarker_pos = int(pos)
	if value.Wire != nil {
		buf[pos] = byte(1)
		pos += 1
		switch x := encoder.Wire_length; {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		for _, w := range value.Wire {
			copy(buf[pos:], w)
			pos += uint(len(w))
		}
	}

	if value.Name != nil {
		buf[pos] = byte(2)
		pos += 1
		switch x := encoder.Name_length; {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		for _, c := range value.Name {
			pos += uint(c.EncodeInto(buf[pos:]))
		}
	}
	encoder.endMarker_pos = int(pos)
}

func (encoder *MarkersEncoder) Encode(value *Markers) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *MarkersParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*Markers, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_startMarker bool = false
	var handled_Wire bool = false
	var handled_argument bool = false
	var handled_Name bool = false
	var handled_endMarker bool = false

	progress := -1
	_ = progress

	value := &Markers{}
	var err error
	var startPos int
	for {
		startPos = reader.Pos()
		if startPos >= reader.Length() {
			break
		}
		typ := enc.TLNum(0)
		l := enc.TLNum(0)
		typ, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		for handled := false; !handled && progress < 5; progress++ {
			switch typ {
			case 1:
				if progress+1 == 1 {
					handled = true
					handled_Wire = true
					value.Wire, err = reader.ReadWire(int(l))
				}
			case 2:
				if progress+1 == 3 {
					handled = true
					handled_Name = true
					value.Name = make(enc.Name, l/2+1)
					startName := reader.Pos()
					endName := startName + int(l)
					for j := range value.Name {
						if reader.Pos() >= endName {
							value.Name = value.Name[:j]
							break
						}
						var err1, err3 error
						value.Name[j].Typ, err1 = enc.ReadTLNum(reader)
						l, err2 := enc.ReadTLNum(reader)
						value.Name[j].Val, err3 = reader.ReadBuf(int(l))
						if err1 != nil || err2 != nil || err3 != nil {
							err = io.ErrUnexpectedEOF
							break
						}
					}
					if err == nil && reader.Pos() != endName {
						err = enc.ErrBufferOverflow
					}
				}
			default:
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				handled = true
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
				switch progress {
				case 0 - 1:
					handled_startMarker = true
					context.startMarker = int(startPos)
				case 1 - 1:
					handled_Wire = true
					value.Wire = nil
				case 2 - 1:
					handled_argument = true
					// base - skip
				case 3 - 1:
					handled_Name = true
					value.Name = nil
				case 4 - 1:
					handled_endMarker = true
					context.endMarker = int(startPos)
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_startMarker && err == nil {
		context.startMarker = int(startPos)
	}
	if !handled_Wire && err == nil {
		value.Wire = nil
	}
	if !handled_argument && err == nil {
		// base - skip
	}
	if !handled_Name && err == nil {
		value.Name = nil
	}
	if !handled_endMarker && err == nil {
		context.endMarker = int(startPos)
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

type NoCopyStructEncoder struct {
	length uint

	wirePlan []uint

	Wire1_length uint

	Wire2_length uint
}

type NoCopyStructParsingContext struct {
}

func (encoder *NoCopyStructEncoder) Init(value *NoCopyStruct) {
	if value.Wire1 != nil {
		encoder.Wire1_length = 0
		for _, c := range value.Wire1 {
			encoder.Wire1_length += uint(len(c))
		}
	}

	if value.Wire2 != nil {
		encoder.Wire2_length = 0
		for _, c := range value.Wire2 {
			encoder.Wire2_length += uint(len(c))
		}
	}

	l := uint(0)
	if value.Wire1 != nil {
		l += 1
		switch x := encoder.Wire1_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Wire1_length
	}
	l += 1
	switch x := value.Number; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}
	if value.Wire2 != nil {
		l += 1
		switch x := encoder.Wire2_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Wire2_length
	}
	encoder.length = l

	wirePlan := make([]uint, 0, 16)
	l = uint(0)
	if value.Wire1 != nil {
		l += 1
		switch x := encoder.Wire1_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		wirePlan = append(wirePlan, l)
		l = 0
		for range value.Wire1 {
			wirePlan = append(wirePlan, l)
			l = 0
		}
	}
	l += 1
	switch x := value.Number; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}
	if value.Wire2 != nil {
		l += 1
		switch x := encoder.Wire2_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		wirePlan = append(wirePlan, l)
		l = 0
		for range value.Wire2 {
			wirePlan = append(wirePlan, l)
			l = 0
		}
	}
	if l > 0 {
		wirePlan = append(wirePlan, l)
	}
	encoder.wirePlan = wirePlan
}

func (context *NoCopyStructParsingContext) Init() {

}

func (encoder *NoCopyStructEncoder) EncodeInto(value *NoCopyStruct, wire enc.Wire) {

	wireIdx := 0
	buf := wire[wireIdx]

	pos := uint(0)

	if value.Wire1 != nil {
		buf[pos] = byte(1)
		pos += 1
		switch x := encoder.Wire1_length; {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		wireIdx++
		pos = 0
		if wireIdx < len(wire) {
			buf = wire[wireIdx]
		} else {
			buf = nil
		}
		for _, w := range value.Wire1 {
			wire[wireIdx] = w
			wireIdx++
			pos = 0
			if wireIdx < len(wire) {
				buf = wire[wireIdx]
			} else {
				buf = nil
			}
		}
	}
	buf[pos] = byte(2)
	pos += 1
	switch x := value.Number; {
	case x <= 0xff:
		buf[pos] = 1
		buf[pos+1] = byte(x)
		pos += 2
	case x <= 0xffff:
		buf[pos] = 2
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
		pos += 3
	case x <= 0xffffffff:
		buf[pos] = 4
		binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
		pos += 5
	default:
		buf[pos] = 8
		binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
		pos += 9
	}
	if value.Wire2 != nil {
		buf[pos] = byte(3)
		pos += 1
		switch x := encoder.Wire2_length; {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		wireIdx++
		pos = 0
		if wireIdx < len(wire) {
			buf = wire[wireIdx]
		} else {
			buf = nil
		}
		for _, w := range value.Wire2 {
			wire[wireIdx] = w
			wireIdx++
			pos = 0
			if wireIdx < len(wire) {
				buf = wire[wireIdx]
			} else {
				buf = nil
			}
		}
	}
}

func (encoder *NoCopyStructEncoder) Encode(value *NoCopyStruct) enc.Wire {

	total := uint(0)
	for _, l := range encoder.wirePlan {
		total += l
	}
	inner := make([]byte, total)
	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		wire[i] = inner[:l]
		inner = inner[l:]
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *NoCopyStructParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*NoCopyStruct, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Wire1 bool = false
	var handled_Number bool = false
	var handled_Wire2 bool = false

	progress := -1
	_ = progress

	value := &NoCopyStruct{}
	var err error
	var startPos int
	for {
		startPos = reader.Pos()
		if startPos >= reader.Length() {
			break
		}
		typ := enc.TLNum(0)
		l := enc.TLNum(0)
		typ, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		if handled := false; true {
			switch typ {
			case 1:
				if true {
					handled = true
					handled_Wire1 = true
					value.Wire1, err = reader.ReadWire(int(l))
				}
			case 2:
				if true {
					handled = true
					handled_Number = true
					value.Number = uint64(0)
					{
						for i := 0; i < int(l); i++ {
							x := byte(0)
							x, err = reader.ReadByte()
							if err != nil {
								if err == io.EOF {
									err = io.ErrUnexpectedEOF
								}
								break
							}
							value.Number = uint64(value.Number<<8) | uint64(x)
						}
					}
				}
			case 3:
				if true {
					handled = true
					handled_Wire2 = true
					value.Wire2, err = reader.ReadWire(int(l))
				}
			default:
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				handled = true
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_Wire1 && err == nil {
		value.Wire1 = nil
	}
	if !handled_Number && err == nil {
		err = enc.ErrSkipRequired{Name: "Number", TypeNum: 2}
	}
	if !handled_Wire2 && err == nil {
		value.Wire2 = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *NoCopyStruct) Encode() enc.Wire {
	encoder := NoCopyStructEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *NoCopyStruct) Bytes() []byte {
	return value.Encode().Join()
}

func ParseNoCopyStruct(reader enc.ParseReader, ignoreCritical bool) (*NoCopyStruct, error) {
	context := NoCopyStructParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type StrFieldEncoder struct {
	length uint
}

type StrFieldParsingContext struct {
}

func (encoder *StrFieldEncoder) Init(value *StrField) {

	l := uint(0)
	l += 1
	switch x := len(value.Str1); {
	case x <= 0xfc:
		l += 1
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}
	l += uint(len(value.Str1))
	if value.Str2 != nil {
		l += 1
		switch x := len(*value.Str2); {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += uint(len(*value.Str2))
	}
	encoder.length = l

}

func (context *StrFieldParsingContext) Init() {

}

func (encoder *StrFieldEncoder) EncodeInto(value *StrField, buf []byte) {

	pos := uint(0)

	buf[pos] = byte(1)
	pos += 1
	switch x := len(value.Str1); {
	case x <= 0xfc:
		buf[pos] = byte(x)
		pos += 1
	case x <= 0xffff:
		buf[pos] = 0xfd
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
		pos += 3
	case x <= 0xffffffff:
		buf[pos] = 0xfe
		binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
		pos += 5
	default:
		buf[pos] = 0xff
		binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
		pos += 9
	}
	copy(buf[pos:], value.Str1)
	pos += uint(len(value.Str1))
	if value.Str2 != nil {
		buf[pos] = byte(2)
		pos += 1
		switch x := len(*value.Str2); {
		case x <= 0xfc:
			buf[pos] = byte(x)
			pos += 1
		case x <= 0xffff:
			buf[pos] = 0xfd
			binary.BigEndian.PutUint16(buf[pos+1:], uint16(x))
			pos += 3
		case x <= 0xffffffff:
			buf[pos] = 0xfe
			binary.BigEndian.PutUint32(buf[pos+1:], uint32(x))
			pos += 5
		default:
			buf[pos] = 0xff
			binary.BigEndian.PutUint64(buf[pos+1:], uint64(x))
			pos += 9
		}
		copy(buf[pos:], *value.Str2)
		pos += uint(len(*value.Str2))
	}
}

func (encoder *StrFieldEncoder) Encode(value *StrField) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StrFieldParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*StrField, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Str1 bool = false
	var handled_Str2 bool = false

	progress := -1
	_ = progress

	value := &StrField{}
	var err error
	var startPos int
	for {
		startPos = reader.Pos()
		if startPos >= reader.Length() {
			break
		}
		typ := enc.TLNum(0)
		l := enc.TLNum(0)
		typ, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		if handled := false; true {
			switch typ {
			case 1:
				if true {
					handled = true
					handled_Str1 = true
					{
						var builder strings.Builder
						_, err = io.CopyN(&builder, reader, int64(l))
						if err == nil {
							value.Str1 = builder.String()
						}
					}
				}
			case 2:
				if true {
					handled = true
					handled_Str2 = true
					{
						var builder strings.Builder
						_, err = io.CopyN(&builder, reader, int64(l))
						if err == nil {
							tempStr := builder.String()
							value.Str2 = &tempStr
						}
					}
				}
			default:
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				handled = true
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_Str1 && err == nil {
		err = enc.ErrSkipRequired{Name: "Str1", TypeNum: 1}
	}
	if !handled_Str2 && err == nil {
		value.Str2 = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *StrField) Encode() enc.Wire {
	encoder := StrFieldEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *StrField) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStrField(reader enc.ParseReader, ignoreCritical bool) (*StrField, error) {
	context := StrFieldParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type FixedUintFieldEncoder struct {
	length uint
}

type FixedUintFieldParsingContext struct {
}

func (encoder *FixedUintFieldEncoder) Init(value *FixedUintField) {

	l := uint(0)
	l += 1
	l += 1 + 1
	if value.U32 != nil {
		l += 1
		l += 1 + 4
	}
	if value.U64 != nil {
		l += 1
		l += 1 + 8
	}
	encoder.length = l

}

func (context *FixedUintFieldParsingContext) Init() {

}

func (encoder *FixedUintFieldEncoder) EncodeInto(value *FixedUintField, buf []byte) {

	pos := uint(0)

	buf[pos] = byte(1)
	pos += 1
	buf[pos] = 1
	buf[pos+1] = byte(value.Byte)
	pos += 2
	if value.U32 != nil {
		buf[pos] = byte(2)
		pos += 1
		buf[pos] = 4
		binary.BigEndian.PutUint32(buf[pos+1:], uint32(*value.U32))
		pos += 5
	}
	if value.U64 != nil {
		buf[pos] = byte(3)
		pos += 1
		buf[pos] = 8
		binary.BigEndian.PutUint64(buf[pos+1:], uint64(*value.U64))
		pos += 9
	}
}

func (encoder *FixedUintFieldEncoder) Encode(value *FixedUintField) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *FixedUintFieldParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*FixedUintField, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Byte bool = false
	var handled_U32 bool = false
	var handled_U64 bool = false

	progress := -1
	_ = progress

	value := &FixedUintField{}
	var err error
	var startPos int
	for {
		startPos = reader.Pos()
		if startPos >= reader.Length() {
			break
		}
		typ := enc.TLNum(0)
		l := enc.TLNum(0)
		typ, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = enc.ReadTLNum(reader)
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		if handled := false; true {
			switch typ {
			case 1:
				if true {
					handled = true
					handled_Byte = true
					value.Byte, err = reader.ReadByte()
					if err == io.EOF {
						err = io.ErrUnexpectedEOF
					}
				}
			case 2:
				if true {
					handled = true
					handled_U32 = true
					{
						tempVal := uint32(0)
						tempVal = uint32(0)
						{
							for i := 0; i < int(l); i++ {
								x := byte(0)
								x, err = reader.ReadByte()
								if err != nil {
									if err == io.EOF {
										err = io.ErrUnexpectedEOF
									}
									break
								}
								tempVal = uint32(tempVal<<8) | uint32(x)
							}
						}
						value.U32 = &tempVal
					}
				}
			case 3:
				if true {
					handled = true
					handled_U64 = true
					{
						tempVal := uint64(0)
						tempVal = uint64(0)
						{
							for i := 0; i < int(l); i++ {
								x := byte(0)
								x, err = reader.ReadByte()
								if err != nil {
									if err == io.EOF {
										err = io.ErrUnexpectedEOF
									}
									break
								}
								tempVal = uint64(tempVal<<8) | uint64(x)
							}
						}
						value.U64 = &tempVal
					}
				}
			default:
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				handled = true
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_Byte && err == nil {
		err = enc.ErrSkipRequired{Name: "Byte", TypeNum: 1}
	}
	if !handled_U32 && err == nil {
		value.U32 = nil
	}
	if !handled_U64 && err == nil {
		value.U64 = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *FixedUintField) Encode() enc.Wire {
	encoder := FixedUintFieldEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *FixedUintField) Bytes() []byte {
	return value.Encode().Join()
}

func ParseFixedUintField(reader enc.ParseReader, ignoreCritical bool) (*FixedUintField, error) {
	context := FixedUintFieldParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}
