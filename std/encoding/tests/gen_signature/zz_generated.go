// Code generated by ndn tlv codegen DO NOT EDIT.
package gen_signature

import (
	"io"

	enc "github.com/named-data/ndnd/std/encoding"
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
	l += uint(1 + enc.Nat(value.H1).EncodingLength())
	encoder.sigCoverStart = int(l)
	if optval, ok := value.H2.Get(); ok {
		l += 1
		l += uint(1 + enc.Nat(optval).EncodingLength())
	}
	if value.C != nil {
		l += 1
		l += uint(enc.TLNum(encoder.C_length).EncodingLength())
		l += encoder.C_length
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		l += uint(enc.TLNum(encoder.Sig_estLen).EncodingLength())
		l += encoder.Sig_estLen
	}

	if optval, ok := value.H3.Get(); ok {
		l += 1
		l += uint(1 + enc.Nat(optval).EncodingLength())
	}
	encoder.length = l

	wirePlan := make([]uint, 0, 8)
	l = uint(0)
	l += 1
	l += uint(1 + enc.Nat(value.H1).EncodingLength())

	if optval, ok := value.H2.Get(); ok {
		l += 1
		l += uint(1 + enc.Nat(optval).EncodingLength())
	}
	if value.C != nil {
		l += 1
		l += uint(enc.TLNum(encoder.C_length).EncodingLength())
		wirePlan = append(wirePlan, l)
		l = 0
		for range value.C {
			wirePlan = append(wirePlan, l)
			l = 0
		}
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		l += uint(enc.TLNum(encoder.Sig_estLen).EncodingLength())
		wirePlan = append(wirePlan, l)
		l = 0
		encoder.Sig_wireIdx = len(wirePlan)
		wirePlan = append(wirePlan, l)
		l = 0
	}

	if optval, ok := value.H3.Get(); ok {
		l += 1
		l += uint(1 + enc.Nat(optval).EncodingLength())
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

	buf[pos] = byte(enc.Nat(value.H1).EncodeInto(buf[pos+1:]))
	pos += uint(1 + buf[pos])
	encoder.sigCoverStart_wireIdx = int(wireIdx)
	encoder.sigCoverStart_pos = int(pos)
	if optval, ok := value.H2.Get(); ok {
		buf[pos] = byte(2)
		pos += 1

		buf[pos] = byte(enc.Nat(optval).EncodeInto(buf[pos+1:]))
		pos += uint(1 + buf[pos])

	}
	if value.C != nil {
		buf[pos] = byte(3)
		pos += 1
		pos += uint(enc.TLNum(encoder.C_length).EncodeInto(buf[pos:]))
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
		pos += uint(enc.TLNum(encoder.Sig_estLen).EncodeInto(buf[pos:]))
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

	if optval, ok := value.H3.Get(); ok {
		buf[pos] = byte(6)
		pos += 1

		buf[pos] = byte(enc.Nat(optval).EncodeInto(buf[pos+1:]))
		pos += uint(1 + buf[pos])

	}
}

func (encoder *T1Encoder) Encode(value *T1) enc.Wire {
	total := uint(0)
	for _, l := range encoder.wirePlan {
		total += l
	}
	content := make([]byte, total)

	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		if l > 0 {
			wire[i] = content[:l]
			content = content[l:]
		}
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *T1ParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*T1, error) {

	var handled_H1 bool = false
	var handled_sigCoverStart bool = false
	var handled_H2 bool = false
	var handled_C bool = false
	var handled_Sig bool = false
	var handled_sigCovered bool = false
	var handled_H3 bool = false

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
		typ, err = reader.ReadTLNum()
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = reader.ReadTLNum()
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}

		err = nil
		for handled := false; !handled && progress < 7; progress++ {
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
						optval := uint64(0)
						optval = uint64(0)
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
								optval = uint64(optval<<8) | uint64(x)
							}
						}
						value.H2.Set(optval)
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
			case 6:
				if progress+1 == 6 {
					handled = true
					handled_H3 = true
					{
						optval := uint64(0)
						optval = uint64(0)
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
								optval = uint64(optval<<8) | uint64(x)
							}
						}
						value.H3.Set(optval)
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
					value.H2.Unset()
				case 3 - 1:
					handled_C = true
					value.C = nil
				case 4 - 1:
					handled_Sig = true
					value.Sig = nil
				case 5 - 1:
					handled_sigCovered = true
					// base - skip
				case 6 - 1:
					handled_H3 = true
					value.H3.Unset()
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
		value.H2.Unset()
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
	if !handled_H3 && err == nil {
		value.H3.Unset()
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
		l += uint(enc.TLNum(encoder.Name_length).EncodingLength())
		l += encoder.Name_length
	}
	encoder.sigCoverStart = int(l)
	encoder.digestCoverStart = int(l)
	if value.C != nil {
		l += 1
		l += uint(enc.TLNum(encoder.C_length).EncodingLength())
		l += encoder.C_length
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		l += uint(enc.TLNum(encoder.Sig_estLen).EncodingLength())
		l += encoder.Sig_estLen
	}
	encoder.digestCoverEnd = int(l)

	encoder.length = l

	wirePlan := make([]uint, 0, 8)
	l = uint(0)
	if value.Name != nil {
		l += 1
		l += uint(enc.TLNum(encoder.Name_length).EncodingLength())
		l += encoder.Name_length
	}

	if value.C != nil {
		l += 1
		l += uint(enc.TLNum(encoder.C_length).EncodingLength())
		wirePlan = append(wirePlan, l)
		l = 0
		for range value.C {
			wirePlan = append(wirePlan, l)
			l = 0
		}
	}
	if encoder.Sig_estLen > 0 {
		l += 1
		l += uint(enc.TLNum(encoder.Sig_estLen).EncodingLength())
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
		pos += uint(enc.TLNum(encoder.Name_length).EncodeInto(buf[pos:]))
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
		pos += uint(enc.TLNum(encoder.C_length).EncodeInto(buf[pos:]))
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
		pos += uint(enc.TLNum(encoder.Sig_estLen).EncodeInto(buf[pos:]))
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
	total := uint(0)
	for _, l := range encoder.wirePlan {
		total += l
	}
	content := make([]byte, total)

	wire := make(enc.Wire, len(encoder.wirePlan))
	for i, l := range encoder.wirePlan {
		if l > 0 {
			wire[i] = content[:l]
			content = content[l:]
		}
	}
	encoder.EncodeInto(value, wire)

	return wire
}

func (context *T2ParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*T2, error) {

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
		typ, err = reader.ReadTLNum()
		if err != nil {
			return nil, enc.ErrFailToParse{TypeNum: 0, Err: err}
		}
		l, err = reader.ReadTLNum()
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
							value.Name[j].Typ, err1 = reader.ReadTLNum()
							l, err2 := reader.ReadTLNum()
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
