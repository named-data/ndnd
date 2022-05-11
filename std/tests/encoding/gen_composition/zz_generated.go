// Generated by the generator, DO NOT modify manually
package gen_composition

import (
	"encoding/binary"
	"io"

	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
)

type IntArrayEncoder struct {
	length uint

	Words_subencoder []struct {
	}
}

type IntArrayParsingContext struct {
}

func (encoder *IntArrayEncoder) Init(value *IntArray) {
	{
		Words_l := len(value.Words)
		encoder.Words_subencoder = make([]struct {
		}, Words_l)
		for i := 0; i < Words_l; i++ {
			pseudoEncoder := &encoder.Words_subencoder[i]
			pseudoValue := struct {
				Words uint64
			}{
				Words: value.Words[i],
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue

				_ = encoder
				_ = value
			}
		}
	}

	l := uint(0)
	if value.Words != nil {
		for seq_i, seq_v := range value.Words {
			pseudoEncoder := &encoder.Words_subencoder[seq_i]
			pseudoValue := struct {
				Words uint64
			}{
				Words: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				l += 1
				switch x := value.Words; {
				case x <= 0xff:
					l += 2
				case x <= 0xffff:
					l += 3
				case x <= 0xffffffff:
					l += 5
				default:
					l += 9
				}

				_ = encoder
				_ = value
			}
		}
	}

	encoder.length = l

}

func (context *IntArrayParsingContext) Init() {

}

func (encoder *IntArrayEncoder) EncodeInto(value *IntArray, buf []byte) {

	pos := uint(0)
	if value.Words != nil {
		for seq_i, seq_v := range value.Words {
			pseudoEncoder := &encoder.Words_subencoder[seq_i]
			pseudoValue := struct {
				Words uint64
			}{
				Words: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				buf[pos] = byte(1)
				pos += 1
				switch x := value.Words; {
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

				_ = encoder
				_ = value
			}
		}
	}

}

func (encoder *IntArrayEncoder) Encode(value *IntArray) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *IntArrayParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*IntArray, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &IntArray{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 1:
				if progress+1 == 0 {
					handled = true
					if value.Words == nil {
						value.Words = make([]uint64, 0)
					}
					{
						pseudoValue := struct {
							Words uint64
						}{}
						{
							value := &pseudoValue
							value.Words = uint64(0)
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
									value.Words = uint64(value.Words<<8) | uint64(x)
								}
							}
							_ = value
						}
						value.Words = append(value.Words, pseudoValue.Words)
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
	startPos = reader.Pos()
	for ; progress < 1; progress++ {
		switch progress {
		case 0 - 1:

		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *IntArray) Encode() enc.Wire {
	encoder := IntArrayEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *IntArray) Bytes() []byte {
	return value.Encode().Join()
}

func ParseIntArray(reader enc.ParseReader, ignoreCritical bool) (*IntArray, error) {
	context := IntArrayParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type NameArrayEncoder struct {
	length uint

	Names_subencoder []struct {
		Names_length uint
	}
}

type NameArrayParsingContext struct {
}

func (encoder *NameArrayEncoder) Init(value *NameArray) {
	{
		Names_l := len(value.Names)
		encoder.Names_subencoder = make([]struct {
			Names_length uint
		}, Names_l)
		for i := 0; i < Names_l; i++ {
			pseudoEncoder := &encoder.Names_subencoder[i]
			pseudoValue := struct {
				Names enc.Name
			}{
				Names: value.Names[i],
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Names != nil {
					encoder.Names_length = 0
					for _, c := range value.Names {
						encoder.Names_length += uint(c.EncodingLength())
					}
				}

				_ = encoder
				_ = value
			}
		}
	}

	l := uint(0)
	if value.Names != nil {
		for seq_i, seq_v := range value.Names {
			pseudoEncoder := &encoder.Names_subencoder[seq_i]
			pseudoValue := struct {
				Names enc.Name
			}{
				Names: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Names != nil {
					l += 1
					switch x := encoder.Names_length; {
					case x <= 0xfc:
						l += 1
					case x <= 0xffff:
						l += 3
					case x <= 0xffffffff:
						l += 5
					default:
						l += 9
					}
					l += encoder.Names_length
				}

				_ = encoder
				_ = value
			}
		}
	}

	encoder.length = l

}

func (context *NameArrayParsingContext) Init() {

}

func (encoder *NameArrayEncoder) EncodeInto(value *NameArray, buf []byte) {

	pos := uint(0)
	if value.Names != nil {
		for seq_i, seq_v := range value.Names {
			pseudoEncoder := &encoder.Names_subencoder[seq_i]
			pseudoValue := struct {
				Names enc.Name
			}{
				Names: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Names != nil {
					buf[pos] = byte(7)
					pos += 1
					switch x := encoder.Names_length; {
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
					for _, c := range value.Names {
						pos += uint(c.EncodeInto(buf[pos:]))
					}
				}

				_ = encoder
				_ = value
			}
		}
	}

}

func (encoder *NameArrayEncoder) Encode(value *NameArray) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *NameArrayParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*NameArray, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &NameArray{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 7:
				if progress+1 == 0 {
					handled = true
					if value.Names == nil {
						value.Names = make([]enc.Name, 0)
					}
					{
						pseudoValue := struct {
							Names enc.Name
						}{}
						{
							value := &pseudoValue
							value.Names = make(enc.Name, 0)
							startName := reader.Pos()
							endName := startName + int(l)
							for reader.Pos() < endName {
								c, err := enc.ReadComponent(reader)
								if err != nil {
									break
								}
								value.Names = append(value.Names, *c)
							}
							if err != nil && reader.Pos() != endName {
								err = enc.ErrBufferOverflow
							}

							_ = value
						}
						value.Names = append(value.Names, pseudoValue.Names)
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
	startPos = reader.Pos()
	for ; progress < 1; progress++ {
		switch progress {
		case 0 - 1:

		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *NameArray) Encode() enc.Wire {
	encoder := NameArrayEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *NameArray) Bytes() []byte {
	return value.Encode().Join()
}

func ParseNameArray(reader enc.ParseReader, ignoreCritical bool) (*NameArray, error) {
	context := NameArrayParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type InnerEncoder struct {
	length uint
}

type InnerParsingContext struct {
}

func (encoder *InnerEncoder) Init(value *Inner) {

	l := uint(0)
	l += 1
	switch x := value.Num; {
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

func (context *InnerParsingContext) Init() {

}

func (encoder *InnerEncoder) EncodeInto(value *Inner, buf []byte) {

	pos := uint(0)
	buf[pos] = byte(1)
	pos += 1
	switch x := value.Num; {
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

func (encoder *InnerEncoder) Encode(value *Inner) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *InnerParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*Inner, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &Inner{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 1:
				if progress+1 == 0 {
					handled = true
					value.Num = uint64(0)
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
							value.Num = uint64(value.Num<<8) | uint64(x)
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
					err = enc.ErrSkipRequired{TypeNum: 1}
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}
	startPos = reader.Pos()
	for ; progress < 1; progress++ {
		switch progress {
		case 0 - 1:
			err = enc.ErrSkipRequired{TypeNum: 1}
		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *Inner) Encode() enc.Wire {
	encoder := InnerEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *Inner) Bytes() []byte {
	return value.Encode().Join()
}

func ParseInner(reader enc.ParseReader, ignoreCritical bool) (*Inner, error) {
	context := InnerParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type NestedEncoder struct {
	length uint

	Val_encoder InnerEncoder
}

type NestedParsingContext struct {
	Val_context InnerParsingContext
}

func (encoder *NestedEncoder) Init(value *Nested) {
	if value.Val != nil {
		encoder.Val_encoder.Init(value.Val)
	}
	l := uint(0)
	if value.Val != nil {
		l += 1
		switch x := encoder.Val_encoder.length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Val_encoder.length
	}

	encoder.length = l

}

func (context *NestedParsingContext) Init() {
	context.Val_context.Init()
}

func (encoder *NestedEncoder) EncodeInto(value *Nested, buf []byte) {

	pos := uint(0)
	if value.Val != nil {
		buf[pos] = byte(2)
		pos += 1
		switch x := encoder.Val_encoder.length; {
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
		if encoder.Val_encoder.length > 0 {
			encoder.Val_encoder.EncodeInto(value.Val, buf[pos:])
			pos += encoder.Val_encoder.length
		}
	}

}

func (encoder *NestedEncoder) Encode(value *Nested) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *NestedParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*Nested, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &Nested{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 2:
				if progress+1 == 0 {
					handled = true
					value.Val, err = context.Val_context.Parse(reader.Delegate(int(l)), ignoreCritical)
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
					value.Val = nil
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}
	startPos = reader.Pos()
	for ; progress < 1; progress++ {
		switch progress {
		case 0 - 1:
			value.Val = nil
		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *Nested) Encode() enc.Wire {
	encoder := NestedEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *Nested) Bytes() []byte {
	return value.Encode().Join()
}

func ParseNested(reader enc.ParseReader, ignoreCritical bool) (*Nested, error) {
	context := NestedParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type NestedSeqEncoder struct {
	length uint

	Vals_subencoder []struct {
		Vals_encoder InnerEncoder
	}
}

type NestedSeqParsingContext struct {
	Vals_context InnerParsingContext
}

func (encoder *NestedSeqEncoder) Init(value *NestedSeq) {
	{
		Vals_l := len(value.Vals)
		encoder.Vals_subencoder = make([]struct {
			Vals_encoder InnerEncoder
		}, Vals_l)
		for i := 0; i < Vals_l; i++ {
			pseudoEncoder := &encoder.Vals_subencoder[i]
			pseudoValue := struct {
				Vals *Inner
			}{
				Vals: value.Vals[i],
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Vals != nil {
					encoder.Vals_encoder.Init(value.Vals)
				}
				_ = encoder
				_ = value
			}
		}
	}

	l := uint(0)
	if value.Vals != nil {
		for seq_i, seq_v := range value.Vals {
			pseudoEncoder := &encoder.Vals_subencoder[seq_i]
			pseudoValue := struct {
				Vals *Inner
			}{
				Vals: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Vals != nil {
					l += 1
					switch x := encoder.Vals_encoder.length; {
					case x <= 0xfc:
						l += 1
					case x <= 0xffff:
						l += 3
					case x <= 0xffffffff:
						l += 5
					default:
						l += 9
					}
					l += encoder.Vals_encoder.length
				}

				_ = encoder
				_ = value
			}
		}
	}

	encoder.length = l

}

func (context *NestedSeqParsingContext) Init() {
	context.Vals_context.Init()
}

func (encoder *NestedSeqEncoder) EncodeInto(value *NestedSeq, buf []byte) {

	pos := uint(0)
	if value.Vals != nil {
		for seq_i, seq_v := range value.Vals {
			pseudoEncoder := &encoder.Vals_subencoder[seq_i]
			pseudoValue := struct {
				Vals *Inner
			}{
				Vals: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Vals != nil {
					buf[pos] = byte(3)
					pos += 1
					switch x := encoder.Vals_encoder.length; {
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
					if encoder.Vals_encoder.length > 0 {
						encoder.Vals_encoder.EncodeInto(value.Vals, buf[pos:])
						pos += encoder.Vals_encoder.length
					}
				}

				_ = encoder
				_ = value
			}
		}
	}

}

func (encoder *NestedSeqEncoder) Encode(value *NestedSeq) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *NestedSeqParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*NestedSeq, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &NestedSeq{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 3:
				if progress+1 == 0 {
					handled = true
					if value.Vals == nil {
						value.Vals = make([]*Inner, 0)
					}
					{
						pseudoValue := struct {
							Vals *Inner
						}{}
						{
							value := &pseudoValue
							value.Vals, err = context.Vals_context.Parse(reader.Delegate(int(l)), ignoreCritical)
							_ = value
						}
						value.Vals = append(value.Vals, pseudoValue.Vals)
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
	startPos = reader.Pos()
	for ; progress < 1; progress++ {
		switch progress {
		case 0 - 1:

		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *NestedSeq) Encode() enc.Wire {
	encoder := NestedSeqEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *NestedSeq) Bytes() []byte {
	return value.Encode().Join()
}

func ParseNestedSeq(reader enc.ParseReader, ignoreCritical bool) (*NestedSeq, error) {
	context := NestedSeqParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type InnerWire1Encoder struct {
	length uint

	wirePlan []uint

	Wire1_length uint
}

type InnerWire1ParsingContext struct {
}

func (encoder *InnerWire1Encoder) Init(value *InnerWire1) {
	if value.Wire1 != nil {
		encoder.Wire1_length = 0
		for _, c := range value.Wire1 {
			encoder.Wire1_length += uint(len(c))
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

	if value.Num != nil {
		l += 1
		switch x := *value.Num; {
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

	encoder.length = l

	wirePlan := make([]uint, 0)
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

	if value.Num != nil {
		l += 1
		switch x := *value.Num; {
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

	if l > 0 {
		wirePlan = append(wirePlan, l)
	}
	encoder.wirePlan = wirePlan
}

func (context *InnerWire1ParsingContext) Init() {

}

func (encoder *InnerWire1Encoder) EncodeInto(value *InnerWire1, wire enc.Wire) {

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

	if value.Num != nil {
		buf[pos] = byte(2)
		pos += 1
		switch x := *value.Num; {
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

}

func (encoder *InnerWire1Encoder) Encode(value *InnerWire1) enc.Wire {

	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		if l > 0 {
			wire[i] = make([]byte, l)
		}
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *InnerWire1ParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*InnerWire1, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &InnerWire1{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 1:
				if progress+1 == 0 {
					handled = true
					value.Wire1, err = reader.ReadWire(int(l))

				}
			case 2:
				if progress+1 == 1 {
					handled = true
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
						value.Num = &tempVal
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
					value.Wire1 = nil
				case 1 - 1:
					value.Num = nil
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}
	startPos = reader.Pos()
	for ; progress < 2; progress++ {
		switch progress {
		case 0 - 1:
			value.Wire1 = nil
		case 1 - 1:
			value.Num = nil
		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

type InnerWire2Encoder struct {
	length uint

	wirePlan []uint

	Wire2_length uint
}

type InnerWire2ParsingContext struct {
}

func (encoder *InnerWire2Encoder) Init(value *InnerWire2) {
	if value.Wire2 != nil {
		encoder.Wire2_length = 0
		for _, c := range value.Wire2 {
			encoder.Wire2_length += uint(len(c))
		}
	}

	l := uint(0)
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

	wirePlan := make([]uint, 0)
	l = uint(0)
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

func (context *InnerWire2ParsingContext) Init() {

}

func (encoder *InnerWire2Encoder) EncodeInto(value *InnerWire2, wire enc.Wire) {

	wireIdx := 0
	buf := wire[wireIdx]

	pos := uint(0)
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

func (encoder *InnerWire2Encoder) Encode(value *InnerWire2) enc.Wire {

	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		if l > 0 {
			wire[i] = make([]byte, l)
		}
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *InnerWire2ParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*InnerWire2, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &InnerWire2{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 3:
				if progress+1 == 0 {
					handled = true
					value.Wire2, err = reader.ReadWire(int(l))

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
					value.Wire2 = nil
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}
	startPos = reader.Pos()
	for ; progress < 1; progress++ {
		switch progress {
		case 0 - 1:
			value.Wire2 = nil
		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

type NestedWireEncoder struct {
	length uint

	wirePlan []uint

	W1_encoder InnerWire1Encoder

	W2_encoder InnerWire2Encoder
}

type NestedWireParsingContext struct {
	W1_context InnerWire1ParsingContext

	W2_context InnerWire2ParsingContext
}

func (encoder *NestedWireEncoder) Init(value *NestedWire) {
	if value.W1 != nil {
		encoder.W1_encoder.Init(value.W1)
	}

	if value.W2 != nil {
		encoder.W2_encoder.Init(value.W2)
	}
	l := uint(0)
	if value.W1 != nil {
		l += 1
		switch x := encoder.W1_encoder.length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.W1_encoder.length
	}

	l += 1
	switch x := value.N; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}

	if value.W2 != nil {
		l += 1
		switch x := encoder.W2_encoder.length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.W2_encoder.length
	}

	encoder.length = l

	wirePlan := make([]uint, 0)
	l = uint(0)
	if value.W1 != nil {
		l += 1
		switch x := encoder.W1_encoder.length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		if encoder.W1_encoder.length > 0 {
			l += encoder.W1_encoder.wirePlan[0]
			for i := 1; i < len(encoder.W1_encoder.wirePlan); i++ {
				wirePlan = append(wirePlan, l)
				l = 0
				l = encoder.W1_encoder.wirePlan[i]
			}
			if l == 0 {
				wirePlan = append(wirePlan, l)
				l = 0
			}
		}
	}

	l += 1
	switch x := value.N; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}

	if value.W2 != nil {
		l += 1
		switch x := encoder.W2_encoder.length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		if encoder.W2_encoder.length > 0 {
			l += encoder.W2_encoder.wirePlan[0]
			for i := 1; i < len(encoder.W2_encoder.wirePlan); i++ {
				wirePlan = append(wirePlan, l)
				l = 0
				l = encoder.W2_encoder.wirePlan[i]
			}
			if l == 0 {
				wirePlan = append(wirePlan, l)
				l = 0
			}
		}
	}

	if l > 0 {
		wirePlan = append(wirePlan, l)
	}
	encoder.wirePlan = wirePlan
}

func (context *NestedWireParsingContext) Init() {
	context.W1_context.Init()

	context.W2_context.Init()
}

func (encoder *NestedWireEncoder) EncodeInto(value *NestedWire, wire enc.Wire) {

	wireIdx := 0
	buf := wire[wireIdx]

	pos := uint(0)
	if value.W1 != nil {
		buf[pos] = byte(4)
		pos += 1
		switch x := encoder.W1_encoder.length; {
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
		if encoder.W1_encoder.length > 0 {
			{
				subWire := make(enc.Wire, len(encoder.W1_encoder.wirePlan))
				subWire[0] = buf[pos:]
				for i := 1; i < len(subWire); i++ {
					subWire[i] = wire[wireIdx+i]
				}
				encoder.W1_encoder.EncodeInto(value.W1, subWire)
				for i := 1; i < len(subWire); i++ {
					wire[wireIdx+i] = subWire[i]
				}
				if lastL := encoder.W1_encoder.wirePlan[len(subWire)-1]; lastL > 0 {
					wireIdx += len(subWire) - 1
					if len(subWire) > 1 {
						pos = lastL
					} else {
						pos += lastL
					}
				} else {
					wireIdx += len(subWire)
					pos = 0
				}
				if wireIdx < len(wire) {
					buf = wire[wireIdx]
				} else {
					buf = nil
				}
			}
		}
	}

	buf[pos] = byte(5)
	pos += 1
	switch x := value.N; {
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

	if value.W2 != nil {
		buf[pos] = byte(6)
		pos += 1
		switch x := encoder.W2_encoder.length; {
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
		if encoder.W2_encoder.length > 0 {
			{
				subWire := make(enc.Wire, len(encoder.W2_encoder.wirePlan))
				subWire[0] = buf[pos:]
				for i := 1; i < len(subWire); i++ {
					subWire[i] = wire[wireIdx+i]
				}
				encoder.W2_encoder.EncodeInto(value.W2, subWire)
				for i := 1; i < len(subWire); i++ {
					wire[wireIdx+i] = subWire[i]
				}
				if lastL := encoder.W2_encoder.wirePlan[len(subWire)-1]; lastL > 0 {
					wireIdx += len(subWire) - 1
					if len(subWire) > 1 {
						pos = lastL
					} else {
						pos += lastL
					}
				} else {
					wireIdx += len(subWire)
					pos = 0
				}
				if wireIdx < len(wire) {
					buf = wire[wireIdx]
				} else {
					buf = nil
				}
			}
		}
	}

}

func (encoder *NestedWireEncoder) Encode(value *NestedWire) enc.Wire {

	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		if l > 0 {
			wire[i] = make([]byte, l)
		}
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *NestedWireParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*NestedWire, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}
	progress := -1
	value := &NestedWire{}
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
		for handled := false; !handled; progress++ {
			switch typ {
			case 4:
				if progress+1 == 0 {
					handled = true
					value.W1, err = context.W1_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			case 5:
				if progress+1 == 1 {
					handled = true
					value.N = uint64(0)
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
							value.N = uint64(value.N<<8) | uint64(x)
						}
					}
				}
			case 6:
				if progress+1 == 2 {
					handled = true
					value.W2, err = context.W2_context.Parse(reader.Delegate(int(l)), ignoreCritical)
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
					value.W1 = nil
				case 1 - 1:
					err = enc.ErrSkipRequired{TypeNum: 5}
				case 2 - 1:
					value.W2 = nil
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}
	startPos = reader.Pos()
	for ; progress < 3; progress++ {
		switch progress {
		case 0 - 1:
			value.W1 = nil
		case 1 - 1:
			err = enc.ErrSkipRequired{TypeNum: 5}
		case 2 - 1:
			value.W2 = nil
		}
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (value *NestedWire) Encode() enc.Wire {
	encoder := NestedWireEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *NestedWire) Bytes() []byte {
	return value.Encode().Join()
}

func ParseNestedWire(reader enc.ParseReader, ignoreCritical bool) (*NestedWire, error) {
	context := NestedWireParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}