// Code generated by ndn tlv codegen DO NOT EDIT.
package gen_signature

import (
	"encoding/binary"
	"io"

	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
)

type T1Encoder struct {
	length uint

	wirePlan []uint

	sigCoverStart         int
	sigCoverStart_wireIdx int
	sigCoverStart_pos     int

	C_length    uint
	Sig_wireIdx int
	Sig_estLen  uint
	sigCovered  enc.Wire
}

type T1ParsingContext struct {
	sigCoverStart int

	sigCovered enc.Wire
}

func (encoder *T1Encoder) Init(value *T1) {

	if value.C != nil {
		encoder.C_length = 0
		for _, c := range value.C {
			encoder.C_length += uint(len(c))
		}
	}
	encoder.Sig_wireIdx = -1

	l := uint(0)
	l += 1
	switch x := value.H1; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}
	encoder.sigCoverStart = int(l)
	if value.H2 != nil {
		l += 1
		switch x := *value.H2; {
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
	if value.C != nil {
		l += 1
		switch x := encoder.C_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.C_length
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		switch x := encoder.Sig_estLen; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Sig_estLen
	}

	encoder.length = l

	wirePlan := make([]uint, 0)
	l = uint(0)
	l += 1
	switch x := value.H1; {
	case x <= 0xff:
		l += 2
	case x <= 0xffff:
		l += 3
	case x <= 0xffffffff:
		l += 5
	default:
		l += 9
	}

	if value.H2 != nil {
		l += 1
		switch x := *value.H2; {
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
	if value.C != nil {
		l += 1
		switch x := encoder.C_length; {
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
		for range value.C {
			wirePlan = append(wirePlan, l)
			l = 0
		}
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		switch x := encoder.Sig_estLen; {
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
		encoder.Sig_wireIdx = len(wirePlan)
		wirePlan = append(wirePlan, l)
		l = 0
	}

	if l > 0 {
		wirePlan = append(wirePlan, l)
	}
	encoder.wirePlan = wirePlan
}

func (context *T1ParsingContext) Init() {

	context.sigCovered = make(enc.Wire, 0)

}

func (encoder *T1Encoder) EncodeInto(value *T1, wire enc.Wire) {

	wireIdx := 0
	buf := wire[wireIdx]

	pos := uint(0)

	buf[pos] = byte(1)
	pos += 1
	switch x := value.H1; {
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
	encoder.sigCoverStart_wireIdx = int(wireIdx)
	encoder.sigCoverStart_pos = int(pos)
	if value.H2 != nil {
		buf[pos] = byte(2)
		pos += 1
		switch x := *value.H2; {
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
	if value.C != nil {
		buf[pos] = byte(3)
		pos += 1
		switch x := encoder.C_length; {
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
		for _, w := range value.C {
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
	if encoder.Sig_estLen > 0 {
		startPos := int(pos)
		buf[pos] = byte(4)
		pos += 1
		switch x := encoder.Sig_estLen; {
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
		if encoder.sigCoverStart_wireIdx == int(wireIdx) {
			coveredPart := buf[encoder.sigCoverStart:startPos]
			encoder.sigCovered = append(encoder.sigCovered, coveredPart)
		} else {
			coverStart := wire[encoder.sigCoverStart_wireIdx][encoder.sigCoverStart:]
			encoder.sigCovered = append(encoder.sigCovered, coverStart)
			for i := encoder.sigCoverStart_wireIdx + 1; i < int(wireIdx); i++ {
				encoder.sigCovered = append(encoder.sigCovered, wire[i])
			}
			coverEnd := buf[:startPos]
			encoder.sigCovered = append(encoder.sigCovered, coverEnd)
		}
		wireIdx++
		pos = 0
		if wireIdx < len(wire) {
			buf = wire[wireIdx]
		} else {
			buf = nil
		}
		wireIdx++
		pos = 0
		if wireIdx < len(wire) {
			buf = wire[wireIdx]
		} else {
			buf = nil
		}
	}

}

func (encoder *T1Encoder) Encode(value *T1) enc.Wire {

	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		if l > 0 {
			wire[i] = make([]byte, l)
		}
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *T1ParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*T1, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_H1 bool = false
	var handled_sigCoverStart bool = false
	var handled_H2 bool = false
	var handled_C bool = false
	var handled_Sig bool = false
	var handled_sigCovered bool = false

	progress := -1
	_ = progress

	value := &T1{}
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
		for handled := false; !handled && progress < 6; progress++ {
			switch typ {
			case 1:
				if progress+1 == 0 {
					handled = true
					handled_H1 = true
					value.H1 = uint64(0)
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
							value.H1 = uint64(value.H1<<8) | uint64(x)
						}
					}
				}
			case 2:
				if progress+1 == 2 {
					handled = true
					handled_H2 = true
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
						value.H2 = &tempVal
					}
				}
			case 3:
				if progress+1 == 3 {
					handled = true
					handled_C = true
					value.C, err = reader.ReadWire(int(l))
				}
			case 4:
				if progress+1 == 4 {
					handled = true
					handled_Sig = true
					value.Sig, err = reader.ReadWire(int(l))
					if err == nil {
						coveredPart := reader.Range(context.sigCoverStart, startPos)
						context.sigCovered = append(context.sigCovered, coveredPart...)
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
					handled_H1 = true
					err = enc.ErrSkipRequired{Name: "H1", TypeNum: 1}
				case 1 - 1:
					handled_sigCoverStart = true
					context.sigCoverStart = int(startPos)
				case 2 - 1:
					handled_H2 = true
					value.H2 = nil
				case 3 - 1:
					handled_C = true
					value.C = nil
				case 4 - 1:
					handled_Sig = true
					value.Sig = nil
				case 5 - 1:
					handled_sigCovered = true
					// base - skip
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_H1 && err == nil {
		err = enc.ErrSkipRequired{Name: "H1", TypeNum: 1}
	}
	if !handled_sigCoverStart && err == nil {
		context.sigCoverStart = int(startPos)
	}
	if !handled_H2 && err == nil {
		value.H2 = nil
	}
	if !handled_C && err == nil {
		value.C = nil
	}
	if !handled_Sig && err == nil {
		value.Sig = nil
	}
	if !handled_sigCovered && err == nil {
		// base - skip
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

type T2Encoder struct {
	length uint

	wirePlan []uint

	Name_length              uint
	Name_needDigest          bool
	Name_wireIdx             int
	Name_pos                 uint
	sigCoverStart            int
	sigCoverStart_wireIdx    int
	sigCoverStart_pos        int
	digestCoverStart         int
	digestCoverStart_wireIdx int
	digestCoverStart_pos     int
	C_length                 uint
	Sig_wireIdx              int
	Sig_estLen               uint
	digestCoverEnd           int
	digestCoverEnd_wireIdx   int
	digestCoverEnd_pos       int
	sigCovered               enc.Wire
}

type T2ParsingContext struct {
	Name_wireIdx     int
	Name_pos         uint
	sigCoverStart    int
	digestCoverStart int

	digestCoverEnd int
	sigCovered     enc.Wire
}

func (encoder *T2Encoder) Init(value *T2) {
	encoder.Name_wireIdx = -1
	encoder.Name_length = 0
	if value.Name != nil {
		if len(value.Name) > 0 && value.Name[len(value.Name)-1].Typ == enc.TypeParametersSha256DigestComponent {
			value.Name = value.Name[:len(value.Name)-1]
		}
		if encoder.Name_needDigest {
			value.Name = append(value.Name, enc.Component{
				Typ: enc.TypeParametersSha256DigestComponent,
				Val: make([]byte, 32),
			})
		}
		for _, c := range value.Name {
			encoder.Name_length += uint(c.EncodingLength())
		}
	}

	if value.C != nil {
		encoder.C_length = 0
		for _, c := range value.C {
			encoder.C_length += uint(len(c))
		}
	}
	encoder.Sig_wireIdx = -1

	l := uint(0)
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
	encoder.sigCoverStart = int(l)
	encoder.digestCoverStart = int(l)
	if value.C != nil {
		l += 1
		switch x := encoder.C_length; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.C_length
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		switch x := encoder.Sig_estLen; {
		case x <= 0xfc:
			l += 1
		case x <= 0xffff:
			l += 3
		case x <= 0xffffffff:
			l += 5
		default:
			l += 9
		}
		l += encoder.Sig_estLen
	}
	encoder.digestCoverEnd = int(l)

	encoder.length = l

	wirePlan := make([]uint, 0)
	l = uint(0)
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

	if value.C != nil {
		l += 1
		switch x := encoder.C_length; {
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
		for range value.C {
			wirePlan = append(wirePlan, l)
			l = 0
		}
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		switch x := encoder.Sig_estLen; {
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
		encoder.Sig_wireIdx = len(wirePlan)
		wirePlan = append(wirePlan, l)
		l = 0
	}

	if l > 0 {
		wirePlan = append(wirePlan, l)
	}
	encoder.wirePlan = wirePlan
}

func (context *T2ParsingContext) Init() {

	context.sigCovered = make(enc.Wire, 0)

}

func (encoder *T2Encoder) EncodeInto(value *T2, wire enc.Wire) {

	wireIdx := 0
	buf := wire[wireIdx]

	pos := uint(0)

	if value.Name != nil {
		buf[pos] = byte(1)
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
		sigCoverStart := pos

		i := 0
		for i = 0; i < len(value.Name)-1; i++ {
			c := value.Name[i]
			pos += uint(c.EncodeInto(buf[pos:]))
		}
		sigCoverEnd := pos
		encoder.Name_wireIdx = int(wireIdx)
		if len(value.Name) > 0 {
			encoder.Name_pos = pos + 2
			c := value.Name[i]
			pos += uint(c.EncodeInto(buf[pos:]))
			if !encoder.Name_needDigest {
				sigCoverEnd = pos
			}
		}
		encoder.sigCovered = append(encoder.sigCovered, buf[sigCoverStart:sigCoverEnd])
	}
	encoder.sigCoverStart_wireIdx = int(wireIdx)
	encoder.sigCoverStart_pos = int(pos)
	encoder.digestCoverStart_wireIdx = int(wireIdx)
	encoder.digestCoverStart_pos = int(pos)
	if value.C != nil {
		buf[pos] = byte(3)
		pos += 1
		switch x := encoder.C_length; {
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
		for _, w := range value.C {
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
	if encoder.Sig_estLen > 0 {
		startPos := int(pos)
		buf[pos] = byte(4)
		pos += 1
		switch x := encoder.Sig_estLen; {
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
		if encoder.sigCoverStart_wireIdx == int(wireIdx) {
			coveredPart := buf[encoder.sigCoverStart:startPos]
			encoder.sigCovered = append(encoder.sigCovered, coveredPart)
		} else {
			coverStart := wire[encoder.sigCoverStart_wireIdx][encoder.sigCoverStart:]
			encoder.sigCovered = append(encoder.sigCovered, coverStart)
			for i := encoder.sigCoverStart_wireIdx + 1; i < int(wireIdx); i++ {
				encoder.sigCovered = append(encoder.sigCovered, wire[i])
			}
			coverEnd := buf[:startPos]
			encoder.sigCovered = append(encoder.sigCovered, coverEnd)
		}
		wireIdx++
		pos = 0
		if wireIdx < len(wire) {
			buf = wire[wireIdx]
		} else {
			buf = nil
		}
		wireIdx++
		pos = 0
		if wireIdx < len(wire) {
			buf = wire[wireIdx]
		} else {
			buf = nil
		}
	}
	encoder.digestCoverEnd_wireIdx = int(wireIdx)
	encoder.digestCoverEnd_pos = int(pos)

}

func (encoder *T2Encoder) Encode(value *T2) enc.Wire {

	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		if l > 0 {
			wire[i] = make([]byte, l)
		}
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *T2ParsingContext) Parse(reader enc.ParseReader, ignoreCritical bool) (*T2, error) {
	if reader == nil {
		return nil, enc.ErrBufferOverflow
	}

	var handled_Name bool = false
	var handled_sigCoverStart bool = false
	var handled_digestCoverStart bool = false
	var handled_C bool = false
	var handled_Sig bool = false
	var handled_digestCoverEnd bool = false
	var handled_sigCovered bool = false

	progress := -1
	_ = progress

	value := &T2{}
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
		for handled := false; !handled && progress < 7; progress++ {
			switch typ {
			case 1:
				if progress+1 == 0 {
					handled = true
					handled_Name = true
					{

						value.Name = make(enc.Name, l/2+1)
						startName := reader.Pos()
						endName := startName + int(l)
						sigCoverEnd := endName
						for j := range value.Name {
							var err1, err3 error
							startComponent := reader.Pos()
							if startComponent >= endName {
								value.Name = value.Name[:j]
								break
							}
							value.Name[j].Typ, err1 = enc.ReadTLNum(reader)
							l, err2 := enc.ReadTLNum(reader)
							value.Name[j].Val, err3 = reader.ReadBuf(int(l))
							if err1 != nil || err2 != nil || err3 != nil {
								err = io.ErrUnexpectedEOF
								break
							}
							if value.Name[j].Typ == enc.TypeParametersSha256DigestComponent {
								sigCoverEnd = startComponent
							}
						}
						if err == nil && reader.Pos() != endName {
							err = enc.ErrBufferOverflow
						}
						if err == nil {
							coveredPart := reader.Range(startName, sigCoverEnd)
							context.sigCovered = append(context.sigCovered, coveredPart...)
						}
					}
				}
			case 3:
				if progress+1 == 3 {
					handled = true
					handled_C = true
					value.C, err = reader.ReadWire(int(l))
				}
			case 4:
				if progress+1 == 4 {
					handled = true
					handled_Sig = true
					value.Sig, err = reader.ReadWire(int(l))
					if err == nil {
						coveredPart := reader.Range(context.sigCoverStart, startPos)
						context.sigCovered = append(context.sigCovered, coveredPart...)
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
					handled_Name = true
					value.Name = nil
				case 1 - 1:
					handled_sigCoverStart = true
					context.sigCoverStart = int(startPos)
				case 2 - 1:
					handled_digestCoverStart = true
					context.digestCoverStart = int(startPos)
				case 3 - 1:
					handled_C = true
					value.C = nil
				case 4 - 1:
					handled_Sig = true
					value.Sig = nil
				case 5 - 1:
					handled_digestCoverEnd = true
					context.digestCoverEnd = int(startPos)
				case 6 - 1:
					handled_sigCovered = true
					// base - skip
				}
			}
			if err != nil {
				return nil, enc.ErrFailToParse{TypeNum: typ, Err: err}
			}
		}
	}

	startPos = reader.Pos()
	err = nil

	if !handled_Name && err == nil {
		value.Name = nil
	}
	if !handled_sigCoverStart && err == nil {
		context.sigCoverStart = int(startPos)
	}
	if !handled_digestCoverStart && err == nil {
		context.digestCoverStart = int(startPos)
	}
	if !handled_C && err == nil {
		value.C = nil
	}
	if !handled_Sig && err == nil {
		value.Sig = nil
	}
	if !handled_digestCoverEnd && err == nil {
		context.digestCoverEnd = int(startPos)
	}
	if !handled_sigCovered && err == nil {
		// base - skip
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}