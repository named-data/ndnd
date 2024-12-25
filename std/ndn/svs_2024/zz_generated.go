// Code generated by ndn tlv codegen DO NOT EDIT.
package sync

import (
	"encoding/binary"
	"io"

	enc "github.com/named-data/ndnd/std/encoding"
)

type StateVectorAppParamEncoder struct {
	length uint

	StateVector_encoder StateVectorEncoder
}

type StateVectorAppParamParsingContext struct {
	StateVector_context StateVectorParsingContext
}

func (encoder *StateVectorAppParamEncoder) Init(value *StateVectorAppParam) {
	if value.StateVector != nil {
		encoder.StateVector_encoder.Init(value.StateVector)
	}

	l := uint(0)
	if value.StateVector != nil {
		l += 1
		switch x := encoder.StateVector_encoder.length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.StateVector_encoder.length
	}
	encoder.length = l

}

func (context *StateVectorAppParamParsingContext) Init() {
	context.StateVector_context.Init()
}

func (encoder *StateVectorAppParamEncoder) EncodeInto(value *StateVectorAppParam, buf []byte) {

	pos := uint(0)

	if value.StateVector != nil {
		buf[pos] = byte(201)
		pos += 1
		switch x := encoder.StateVector_encoder.length; {
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
		if encoder.StateVector_encoder.length > 0 {
			encoder.StateVector_encoder.EncodeInto(value.StateVector, buf[pos:])
			pos += encoder.StateVector_encoder.length
		}
	}
}

func (encoder *StateVectorAppParamEncoder) Encode(value *StateVectorAppParam) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StateVectorAppParamParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*StateVectorAppParam, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_StateVector bool = false

	progress := -1
	_ = progress

	value := &StateVectorAppParam{}
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
			case 201:
				if true {
					handled = true
					handled_StateVector = true
					drdr := reader.Delegate(int(l))
					value.StateVector, err = context.StateVector_context.Parse(drdr, ignoreCritical)
					drdr.Free()
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

	if !handled_StateVector && err == nil {
		value.StateVector = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *StateVectorAppParam) Encode() enc.Wire {
	encoder := StateVectorAppParamEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *StateVectorAppParam) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStateVectorAppParam(reader enc.ParseReader, ignoreCritical bool) (*StateVectorAppParam, error) {
	context := StateVectorAppParamParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type StateVectorEncoder struct {
	length uint

	Entries_subencoder []struct {
		Entries_encoder StateVectorEntryEncoder
	}
}

type StateVectorParsingContext struct {
	Entries_context StateVectorEntryParsingContext
}

func (encoder *StateVectorEncoder) Init(value *StateVector) {
	{
		Entries_l := len(value.Entries)
		encoder.Entries_subencoder = make([]struct {
			Entries_encoder StateVectorEntryEncoder
		}, Entries_l)
		for i := 0; i < Entries_l; i++ {
			pseudoEncoder := &encoder.Entries_subencoder[i]
			pseudoValue := struct {
				Entries *StateVectorEntry
			}{
				Entries: value.Entries[i],
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Entries != nil {
					encoder.Entries_encoder.Init(value.Entries)
				}
				_ = encoder
				_ = value
			}
		}
	}

	l := uint(0)
	if value.Entries != nil {
		for seq_i, seq_v := range value.Entries {
			pseudoEncoder := &encoder.Entries_subencoder[seq_i]
			pseudoValue := struct {
				Entries *StateVectorEntry
			}{
				Entries: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Entries != nil {
					l += 1
					switch x := encoder.Entries_encoder.length; {
					case x <= 0xfc:
						l += 1
					case x <= 0xffff:
						l += 3
					case x <= 0xffffffff:
						l += 5
					default:
						l += 9
					}
					l += encoder.Entries_encoder.length
				}
				_ = encoder
				_ = value
			}
		}
	}
	encoder.length = l

}

func (context *StateVectorParsingContext) Init() {
	context.Entries_context.Init()
}

func (encoder *StateVectorEncoder) EncodeInto(value *StateVector, buf []byte) {

	pos := uint(0)

	if value.Entries != nil {
		for seq_i, seq_v := range value.Entries {
			pseudoEncoder := &encoder.Entries_subencoder[seq_i]
			pseudoValue := struct {
				Entries *StateVectorEntry
			}{
				Entries: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Entries != nil {
					buf[pos] = byte(202)
					pos += 1
					switch x := encoder.Entries_encoder.length; {
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
					if encoder.Entries_encoder.length > 0 {
						encoder.Entries_encoder.EncodeInto(value.Entries, buf[pos:])
						pos += encoder.Entries_encoder.length
					}
				}
				_ = encoder
				_ = value
			}
		}
	}
}

func (encoder *StateVectorEncoder) Encode(value *StateVector) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StateVectorParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*StateVector, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Entries bool = false

	progress := -1
	_ = progress

	value := &StateVector{}
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
			case 202:
				if true {
					handled = true
					handled_Entries = true
					if value.Entries == nil {
						value.Entries = make([]*StateVectorEntry, 0)
					}
					{
						pseudoValue := struct {
							Entries *StateVectorEntry
						}{}
						{
							value := &pseudoValue
							drdr := reader.Delegate(int(l))
							value.Entries, err = context.Entries_context.Parse(drdr, ignoreCritical)
							drdr.Free()
							_ = value
						}
						value.Entries = append(value.Entries, pseudoValue.Entries)
					}
					progress--
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

	if !handled_Entries && err == nil {
		// sequence - skip
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *StateVector) Encode() enc.Wire {
	encoder := StateVectorEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *StateVector) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStateVector(reader enc.ParseReader, ignoreCritical bool) (*StateVector, error) {
	context := StateVectorParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type StateVectorEntryEncoder struct {
	length uint

	NodeId_length uint
}

type StateVectorEntryParsingContext struct {
}

func (encoder *StateVectorEntryEncoder) Init(value *StateVectorEntry) {
	if value.NodeId != nil {
		encoder.NodeId_length = 0
		for _, c := range value.NodeId {
			encoder.NodeId_length += uint(c.EncodingLength())
		}
	}

	l := uint(0)
	if value.NodeId != nil {
		l += 1
		switch x := encoder.NodeId_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.NodeId_length
	}
	l += 1
	switch x := value.SeqNo; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}
	encoder.length = l

}

func (context *StateVectorEntryParsingContext) Init() {

}

func (encoder *StateVectorEntryEncoder) EncodeInto(value *StateVectorEntry, buf []byte) {

	pos := uint(0)

	if value.NodeId != nil {
		buf[pos] = byte(7)
		pos += 1
		switch x := encoder.NodeId_length; {
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
		for _, c := range value.NodeId {
			pos += uint(c.EncodeInto(buf[pos:]))
		}
	}
	buf[pos] = byte(204)
	pos += 1
	switch x := value.SeqNo; {
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

func (encoder *StateVectorEntryEncoder) Encode(value *StateVectorEntry) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StateVectorEntryParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*StateVectorEntry, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_NodeId bool = false
	var handled_SeqNo bool = false

	progress := -1
	_ = progress

	value := &StateVectorEntry{}
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
			case 7:
				if true {
					handled = true
					handled_NodeId = true
					value.NodeId = make(enc.Name, l/2+1)
					startName := reader.Pos()
					endName := startName + int(l)
					for j := range value.NodeId {
						if reader.Pos() >= endName {
							value.NodeId = value.NodeId[:j]
							break
						}
						var err1, err3 error
						value.NodeId[j].Typ, err1 = enc.ReadTLNum(reader)
						l, err2 := enc.ReadTLNum(reader)
						value.NodeId[j].Val, err3 = reader.ReadBuf(int(l))
						if err1 != nil || err2 != nil || err3 != nil {
							err = io.ErrUnexpectedEOF
							break
						}
					}
					if err == nil && reader.Pos() != endName {
						err = enc.ErrBufferOverflow
					}
				}
			case 204:
				if true {
					handled = true
					handled_SeqNo = true
					value.SeqNo = uint64(0)
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
							value.SeqNo = uint64(value.SeqNo<<8) | uint64(x)
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

	if !handled_NodeId && err == nil {
		value.NodeId = nil
	}
	if !handled_SeqNo && err == nil {
		err = enc.ErrSkipRequired{Name: "SeqNo", TypeNum: 204}
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *StateVectorEntry) Encode() enc.Wire {
	encoder := StateVectorEntryEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *StateVectorEntry) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStateVectorEntry(reader enc.ParseReader, ignoreCritical bool) (*StateVectorEntry, error) {
	context := StateVectorEntryParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}
