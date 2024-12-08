// Generated by the generator, DO NOT modify manually
package svs

import (
	"encoding/binary"
	"io"

	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
)

type StateVecEntryEncoder struct {
	length uint
}

type StateVecEntryParsingContext struct {
}

func (encoder *StateVecEntryEncoder) Init(value *StateVecEntry) {

	l := uint(0)
	if value.NodeId != nil {
		l += 1
		switch x := len(value.NodeId); {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += uint(len(value.NodeId))
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

func (context *StateVecEntryParsingContext) Init() {

}

func (encoder *StateVecEntryEncoder) EncodeInto(value *StateVecEntry, buf []byte) {

	pos := uint(0)
	if value.NodeId != nil {
		buf[pos] = byte(7)
		pos += 1
		switch x := len(value.NodeId); {
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
		copy(buf[pos:], value.NodeId)
		pos += uint(len(value.NodeId))
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

func (encoder *StateVecEntryEncoder) Encode(value *StateVecEntry) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StateVecEntryParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*StateVecEntry, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &StateVecEntry{}
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
		if true {
			handled := false
			switch typ {
			case 7:
				if true {
					handled = true
					value.NodeId = make([]byte, l)
					_, err = io.ReadFull(reader, value.NodeId)

				}
			case 204:
				if true {
					handled = true
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
				handled = true
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
				switch progress {
				case 0 - 1:
					value.NodeId = nil
				case 1 - 1:
					err = enc.ErrSkipRequired{Name: "SeqNo", TypeNum: 204}
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *StateVecEntry) Encode() enc.Wire {
	encoder := StateVecEntryEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *StateVecEntry) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStateVecEntry(reader enc.ParseReader, ignoreCritical bool) (*StateVecEntry, error) {
	context := StateVecEntryParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type StateVecEncoder struct {
	length uint

	Entries_subencoder []struct {
		Entries_encoder StateVecEntryEncoder
	}
}

type StateVecParsingContext struct {
	Entries_context StateVecEntryParsingContext
}

func (encoder *StateVecEncoder) Init(value *StateVec) {
	{
		Entries_l := len(value.Entries)
		encoder.Entries_subencoder = make([]struct {
			Entries_encoder StateVecEntryEncoder
		}, Entries_l)
		for i := 0; i < Entries_l; i++ {
			pseudoEncoder := &encoder.Entries_subencoder[i]
			pseudoValue := struct {
				Entries *StateVecEntry
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
				Entries *StateVecEntry
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

func (context *StateVecParsingContext) Init() {
	context.Entries_context.Init()
}

func (encoder *StateVecEncoder) EncodeInto(value *StateVec, buf []byte) {

	pos := uint(0)
	if value.Entries != nil {
		for seq_i, seq_v := range value.Entries {
			pseudoEncoder := &encoder.Entries_subencoder[seq_i]
			pseudoValue := struct {
				Entries *StateVecEntry
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

func (encoder *StateVecEncoder) Encode(value *StateVec) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StateVecParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*StateVec, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &StateVec{}
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
		if true {
			handled := false
			switch typ {
			case 202:
				if true {
					handled = true
					if value.Entries == nil {
						value.Entries = make([]*StateVecEntry, 0)
					}
					{
						pseudoValue := struct {
							Entries *StateVecEntry
						}{}
						{
							value := &pseudoValue
							value.Entries, err = context.Entries_context.Parse(reader.Delegate(int(l)), ignoreCritical)
							_ = value
						}
						value.Entries = append(value.Entries, pseudoValue.Entries)
					}
					progress--

				}
			default:
				handled = true
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
				switch progress {
				case 0 - 1:

				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *StateVec) Encode() enc.Wire {
	encoder := StateVecEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *StateVec) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStateVec(reader enc.ParseReader, ignoreCritical bool) (*StateVec, error) {
	context := StateVecParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type StateVecAppParamEncoder struct {
	length uint

	Entries_encoder StateVecEncoder
}

type StateVecAppParamParsingContext struct {
	Entries_context StateVecParsingContext
}

func (encoder *StateVecAppParamEncoder) Init(value *StateVecAppParam) {
	if value.Entries != nil {
		encoder.Entries_encoder.Init(value.Entries)
	}
	l := uint(0)
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

	encoder.length = l

}

func (context *StateVecAppParamParsingContext) Init() {
	context.Entries_context.Init()
}

func (encoder *StateVecAppParamEncoder) EncodeInto(value *StateVecAppParam, buf []byte) {

	pos := uint(0)
	if value.Entries != nil {
		buf[pos] = byte(201)
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

}

func (encoder *StateVecAppParamEncoder) Encode(value *StateVecAppParam) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StateVecAppParamParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*StateVecAppParam, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &StateVecAppParam{}
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
		if true {
			handled := false
			switch typ {
			case 201:
				if true {
					handled = true
					value.Entries, err = context.Entries_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			default:
				handled = true
				if !ignoreCritical && ((typ <= 31) || ((typ & 1) == 1)) {
					return nil, enc.ErrUnrecognizedField{TypeNum: typ}
				}
				err = reader.Skip(int(l))
			}
			if err == nil && !handled {
				switch progress {
				case 0 - 1:
					value.Entries = nil
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *StateVecAppParam) Encode() enc.Wire {
	encoder := StateVecAppParamEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *StateVecAppParam) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStateVecAppParam(reader enc.ParseReader, ignoreCritical bool) (*StateVecAppParam, error) {
	context := StateVecAppParamParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}
