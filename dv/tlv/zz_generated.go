// Code generated by ndn tlv codegen DO NOT EDIT.
package tlv

import (
	"encoding/binary"
	"io"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
)

type PacketEncoder struct {
	Length uint

	Advertisement_encoder AdvertisementEncoder
	PrefixOpList_encoder  PrefixOpListEncoder
}

type PacketParsingContext struct {
	Advertisement_context AdvertisementParsingContext
	PrefixOpList_context  PrefixOpListParsingContext
}

func (encoder *PacketEncoder) Init(value *Packet) {
	if value.Advertisement != nil {
		encoder.Advertisement_encoder.Init(value.Advertisement)
	}
	if value.PrefixOpList != nil {
		encoder.PrefixOpList_encoder.Init(value.PrefixOpList)
	}

	l := uint(0)
	if value.Advertisement != nil {
		l += 1
		l += uint(enc.TLNum(encoder.Advertisement_encoder.Length).EncodingLength())
		l += encoder.Advertisement_encoder.Length
	}
	if value.PrefixOpList != nil {
		l += 3
		l += uint(enc.TLNum(encoder.PrefixOpList_encoder.Length).EncodingLength())
		l += encoder.PrefixOpList_encoder.Length
	}
	encoder.Length = l

}

func (context *PacketParsingContext) Init() {
	context.Advertisement_context.Init()
	context.PrefixOpList_context.Init()
}

func (encoder *PacketEncoder) EncodeInto(value *Packet, buf []byte) {

	pos := uint(0)

	if value.Advertisement != nil {
		buf[pos] = byte(201)
		pos += 1
		pos += uint(enc.TLNum(encoder.Advertisement_encoder.Length).EncodeInto(buf[pos:]))
		if encoder.Advertisement_encoder.Length > 0 {
			encoder.Advertisement_encoder.EncodeInto(value.Advertisement, buf[pos:])
			pos += encoder.Advertisement_encoder.Length
		}
	}
	if value.PrefixOpList != nil {
		buf[pos] = 253
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(301))
		pos += 3
		pos += uint(enc.TLNum(encoder.PrefixOpList_encoder.Length).EncodeInto(buf[pos:]))
		if encoder.PrefixOpList_encoder.Length > 0 {
			encoder.PrefixOpList_encoder.EncodeInto(value.PrefixOpList, buf[pos:])
			pos += encoder.PrefixOpList_encoder.Length
		}
	}
}

func (encoder *PacketEncoder) Encode(value *Packet) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *PacketParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*Packet, error) {

	var handled_Advertisement bool = false
	var handled_PrefixOpList bool = false

	progress := -1
	_ = progress

	value := &Packet{}
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
		if handled := false; true {
			switch typ {
			case 201:
				if true {
					handled = true
					handled_Advertisement = true
					value.Advertisement, err = context.Advertisement_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			case 301:
				if true {
					handled = true
					handled_PrefixOpList = true
					value.PrefixOpList, err = context.PrefixOpList_context.Parse(reader.Delegate(int(l)), ignoreCritical)
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

	if !handled_Advertisement && err == nil {
		value.Advertisement = nil
	}
	if !handled_PrefixOpList && err == nil {
		value.PrefixOpList = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *Packet) Encode() enc.Wire {
	encoder := PacketEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *Packet) Bytes() []byte {
	return value.Encode().Join()
}

func ParsePacket(reader enc.WireView, ignoreCritical bool) (*Packet, error) {
	context := PacketParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type AdvertisementEncoder struct {
	Length uint

	Entries_subencoder []struct {
		Entries_encoder AdvEntryEncoder
	}
}

type AdvertisementParsingContext struct {
	Entries_context AdvEntryParsingContext
}

func (encoder *AdvertisementEncoder) Init(value *Advertisement) {
	{
		Entries_l := len(value.Entries)
		encoder.Entries_subencoder = make([]struct {
			Entries_encoder AdvEntryEncoder
		}, Entries_l)
		for i := 0; i < Entries_l; i++ {
			pseudoEncoder := &encoder.Entries_subencoder[i]
			pseudoValue := struct {
				Entries *AdvEntry
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
				Entries *AdvEntry
			}{
				Entries: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Entries != nil {
					l += 1
					l += uint(enc.TLNum(encoder.Entries_encoder.Length).EncodingLength())
					l += encoder.Entries_encoder.Length
				}
				_ = encoder
				_ = value
			}
		}
	}
	encoder.Length = l

}

func (context *AdvertisementParsingContext) Init() {
	context.Entries_context.Init()
}

func (encoder *AdvertisementEncoder) EncodeInto(value *Advertisement, buf []byte) {

	pos := uint(0)

	if value.Entries != nil {
		for seq_i, seq_v := range value.Entries {
			pseudoEncoder := &encoder.Entries_subencoder[seq_i]
			pseudoValue := struct {
				Entries *AdvEntry
			}{
				Entries: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.Entries != nil {
					buf[pos] = byte(202)
					pos += 1
					pos += uint(enc.TLNum(encoder.Entries_encoder.Length).EncodeInto(buf[pos:]))
					if encoder.Entries_encoder.Length > 0 {
						encoder.Entries_encoder.EncodeInto(value.Entries, buf[pos:])
						pos += encoder.Entries_encoder.Length
					}
				}
				_ = encoder
				_ = value
			}
		}
	}
}

func (encoder *AdvertisementEncoder) Encode(value *Advertisement) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *AdvertisementParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*Advertisement, error) {

	var handled_Entries bool = false

	progress := -1
	_ = progress

	value := &Advertisement{}
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
		if handled := false; true {
			switch typ {
			case 202:
				if true {
					handled = true
					handled_Entries = true
					if value.Entries == nil {
						value.Entries = make([]*AdvEntry, 0)
					}
					{
						pseudoValue := struct {
							Entries *AdvEntry
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

func (value *Advertisement) Encode() enc.Wire {
	encoder := AdvertisementEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *Advertisement) Bytes() []byte {
	return value.Encode().Join()
}

func ParseAdvertisement(reader enc.WireView, ignoreCritical bool) (*Advertisement, error) {
	context := AdvertisementParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type AdvEntryEncoder struct {
	Length uint

	Destination_encoder DestinationEncoder
	NextHop_encoder     DestinationEncoder
}

type AdvEntryParsingContext struct {
	Destination_context DestinationParsingContext
	NextHop_context     DestinationParsingContext
}

func (encoder *AdvEntryEncoder) Init(value *AdvEntry) {
	if value.Destination != nil {
		encoder.Destination_encoder.Init(value.Destination)
	}
	if value.NextHop != nil {
		encoder.NextHop_encoder.Init(value.NextHop)
	}

	l := uint(0)
	if value.Destination != nil {
		l += 1
		l += uint(enc.TLNum(encoder.Destination_encoder.Length).EncodingLength())
		l += encoder.Destination_encoder.Length
	}
	if value.NextHop != nil {
		l += 1
		l += uint(enc.TLNum(encoder.NextHop_encoder.Length).EncodingLength())
		l += encoder.NextHop_encoder.Length
	}
	l += 1
	l += uint(1 + enc.Nat(value.Cost).EncodingLength())
	l += 1
	l += uint(1 + enc.Nat(value.OtherCost).EncodingLength())
	encoder.Length = l

}

func (context *AdvEntryParsingContext) Init() {
	context.Destination_context.Init()
	context.NextHop_context.Init()

}

func (encoder *AdvEntryEncoder) EncodeInto(value *AdvEntry, buf []byte) {

	pos := uint(0)

	if value.Destination != nil {
		buf[pos] = byte(204)
		pos += 1
		pos += uint(enc.TLNum(encoder.Destination_encoder.Length).EncodeInto(buf[pos:]))
		if encoder.Destination_encoder.Length > 0 {
			encoder.Destination_encoder.EncodeInto(value.Destination, buf[pos:])
			pos += encoder.Destination_encoder.Length
		}
	}
	if value.NextHop != nil {
		buf[pos] = byte(206)
		pos += 1
		pos += uint(enc.TLNum(encoder.NextHop_encoder.Length).EncodeInto(buf[pos:]))
		if encoder.NextHop_encoder.Length > 0 {
			encoder.NextHop_encoder.EncodeInto(value.NextHop, buf[pos:])
			pos += encoder.NextHop_encoder.Length
		}
	}
	buf[pos] = byte(208)
	pos += 1

	buf[pos] = byte(enc.Nat(value.Cost).EncodeInto(buf[pos+1:]))
	pos += uint(1 + buf[pos])
	buf[pos] = byte(210)
	pos += 1

	buf[pos] = byte(enc.Nat(value.OtherCost).EncodeInto(buf[pos+1:]))
	pos += uint(1 + buf[pos])
}

func (encoder *AdvEntryEncoder) Encode(value *AdvEntry) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *AdvEntryParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*AdvEntry, error) {

	var handled_Destination bool = false
	var handled_NextHop bool = false
	var handled_Cost bool = false
	var handled_OtherCost bool = false

	progress := -1
	_ = progress

	value := &AdvEntry{}
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
		if handled := false; true {
			switch typ {
			case 204:
				if true {
					handled = true
					handled_Destination = true
					value.Destination, err = context.Destination_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			case 206:
				if true {
					handled = true
					handled_NextHop = true
					value.NextHop, err = context.NextHop_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			case 208:
				if true {
					handled = true
					handled_Cost = true
					value.Cost = uint64(0)
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
							value.Cost = uint64(value.Cost<<8) | uint64(x)
						}
					}
				}
			case 210:
				if true {
					handled = true
					handled_OtherCost = true
					value.OtherCost = uint64(0)
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
							value.OtherCost = uint64(value.OtherCost<<8) | uint64(x)
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

	if !handled_Destination && err == nil {
		value.Destination = nil
	}
	if !handled_NextHop && err == nil {
		value.NextHop = nil
	}
	if !handled_Cost && err == nil {
		err = enc.ErrSkipRequired{Name: "Cost", TypeNum: 208}
	}
	if !handled_OtherCost && err == nil {
		err = enc.ErrSkipRequired{Name: "OtherCost", TypeNum: 210}
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *AdvEntry) Encode() enc.Wire {
	encoder := AdvEntryEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *AdvEntry) Bytes() []byte {
	return value.Encode().Join()
}

func ParseAdvEntry(reader enc.WireView, ignoreCritical bool) (*AdvEntry, error) {
	context := AdvEntryParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type DestinationEncoder struct {
	Length uint

	Name_length uint
}

type DestinationParsingContext struct {
}

func (encoder *DestinationEncoder) Init(value *Destination) {
	if value.Name != nil {
		encoder.Name_length = 0
		for _, c := range value.Name {
			encoder.Name_length += uint(c.EncodingLength())
		}
	}

	l := uint(0)
	if value.Name != nil {
		l += 1
		l += uint(enc.TLNum(encoder.Name_length).EncodingLength())
		l += encoder.Name_length
	}
	encoder.Length = l

}

func (context *DestinationParsingContext) Init() {

}

func (encoder *DestinationEncoder) EncodeInto(value *Destination, buf []byte) {

	pos := uint(0)

	if value.Name != nil {
		buf[pos] = byte(7)
		pos += 1
		pos += uint(enc.TLNum(encoder.Name_length).EncodeInto(buf[pos:]))
		for _, c := range value.Name {
			pos += uint(c.EncodeInto(buf[pos:]))
		}
	}
}

func (encoder *DestinationEncoder) Encode(value *Destination) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *DestinationParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*Destination, error) {

	var handled_Name bool = false

	progress := -1
	_ = progress

	value := &Destination{}
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
		if handled := false; true {
			switch typ {
			case 7:
				if true {
					handled = true
					handled_Name = true
					delegate := reader.Delegate(int(l))
					value.Name, err = delegate.ReadName()
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

	if !handled_Name && err == nil {
		value.Name = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *Destination) Encode() enc.Wire {
	encoder := DestinationEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *Destination) Bytes() []byte {
	return value.Encode().Join()
}

func ParseDestination(reader enc.WireView, ignoreCritical bool) (*Destination, error) {
	context := DestinationParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type PrefixOpListEncoder struct {
	Length uint

	ExitRouter_encoder DestinationEncoder

	PrefixOpAdds_subencoder []struct {
		PrefixOpAdds_encoder PrefixOpAddEncoder
	}
	PrefixOpRemoves_subencoder []struct {
		PrefixOpRemoves_encoder PrefixOpRemoveEncoder
	}
}

type PrefixOpListParsingContext struct {
	ExitRouter_context DestinationParsingContext

	PrefixOpAdds_context    PrefixOpAddParsingContext
	PrefixOpRemoves_context PrefixOpRemoveParsingContext
}

func (encoder *PrefixOpListEncoder) Init(value *PrefixOpList) {
	if value.ExitRouter != nil {
		encoder.ExitRouter_encoder.Init(value.ExitRouter)
	}

	{
		PrefixOpAdds_l := len(value.PrefixOpAdds)
		encoder.PrefixOpAdds_subencoder = make([]struct {
			PrefixOpAdds_encoder PrefixOpAddEncoder
		}, PrefixOpAdds_l)
		for i := 0; i < PrefixOpAdds_l; i++ {
			pseudoEncoder := &encoder.PrefixOpAdds_subencoder[i]
			pseudoValue := struct {
				PrefixOpAdds *PrefixOpAdd
			}{
				PrefixOpAdds: value.PrefixOpAdds[i],
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.PrefixOpAdds != nil {
					encoder.PrefixOpAdds_encoder.Init(value.PrefixOpAdds)
				}
				_ = encoder
				_ = value
			}
		}
	}
	{
		PrefixOpRemoves_l := len(value.PrefixOpRemoves)
		encoder.PrefixOpRemoves_subencoder = make([]struct {
			PrefixOpRemoves_encoder PrefixOpRemoveEncoder
		}, PrefixOpRemoves_l)
		for i := 0; i < PrefixOpRemoves_l; i++ {
			pseudoEncoder := &encoder.PrefixOpRemoves_subencoder[i]
			pseudoValue := struct {
				PrefixOpRemoves *PrefixOpRemove
			}{
				PrefixOpRemoves: value.PrefixOpRemoves[i],
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.PrefixOpRemoves != nil {
					encoder.PrefixOpRemoves_encoder.Init(value.PrefixOpRemoves)
				}
				_ = encoder
				_ = value
			}
		}
	}

	l := uint(0)
	if value.ExitRouter != nil {
		l += 1
		l += uint(enc.TLNum(encoder.ExitRouter_encoder.Length).EncodingLength())
		l += encoder.ExitRouter_encoder.Length
	}
	if value.PrefixOpReset {
		l += 3
		l += 1
	}
	if value.PrefixOpAdds != nil {
		for seq_i, seq_v := range value.PrefixOpAdds {
			pseudoEncoder := &encoder.PrefixOpAdds_subencoder[seq_i]
			pseudoValue := struct {
				PrefixOpAdds *PrefixOpAdd
			}{
				PrefixOpAdds: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.PrefixOpAdds != nil {
					l += 3
					l += uint(enc.TLNum(encoder.PrefixOpAdds_encoder.Length).EncodingLength())
					l += encoder.PrefixOpAdds_encoder.Length
				}
				_ = encoder
				_ = value
			}
		}
	}
	if value.PrefixOpRemoves != nil {
		for seq_i, seq_v := range value.PrefixOpRemoves {
			pseudoEncoder := &encoder.PrefixOpRemoves_subencoder[seq_i]
			pseudoValue := struct {
				PrefixOpRemoves *PrefixOpRemove
			}{
				PrefixOpRemoves: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.PrefixOpRemoves != nil {
					l += 3
					l += uint(enc.TLNum(encoder.PrefixOpRemoves_encoder.Length).EncodingLength())
					l += encoder.PrefixOpRemoves_encoder.Length
				}
				_ = encoder
				_ = value
			}
		}
	}
	encoder.Length = l

}

func (context *PrefixOpListParsingContext) Init() {
	context.ExitRouter_context.Init()

	context.PrefixOpAdds_context.Init()
	context.PrefixOpRemoves_context.Init()
}

func (encoder *PrefixOpListEncoder) EncodeInto(value *PrefixOpList, buf []byte) {

	pos := uint(0)

	if value.ExitRouter != nil {
		buf[pos] = byte(204)
		pos += 1
		pos += uint(enc.TLNum(encoder.ExitRouter_encoder.Length).EncodeInto(buf[pos:]))
		if encoder.ExitRouter_encoder.Length > 0 {
			encoder.ExitRouter_encoder.EncodeInto(value.ExitRouter, buf[pos:])
			pos += encoder.ExitRouter_encoder.Length
		}
	}
	if value.PrefixOpReset {
		buf[pos] = 253
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(302))
		pos += 3
		buf[pos] = byte(0)
		pos += 1
	}
	if value.PrefixOpAdds != nil {
		for seq_i, seq_v := range value.PrefixOpAdds {
			pseudoEncoder := &encoder.PrefixOpAdds_subencoder[seq_i]
			pseudoValue := struct {
				PrefixOpAdds *PrefixOpAdd
			}{
				PrefixOpAdds: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.PrefixOpAdds != nil {
					buf[pos] = 253
					binary.BigEndian.PutUint16(buf[pos+1:], uint16(304))
					pos += 3
					pos += uint(enc.TLNum(encoder.PrefixOpAdds_encoder.Length).EncodeInto(buf[pos:]))
					if encoder.PrefixOpAdds_encoder.Length > 0 {
						encoder.PrefixOpAdds_encoder.EncodeInto(value.PrefixOpAdds, buf[pos:])
						pos += encoder.PrefixOpAdds_encoder.Length
					}
				}
				_ = encoder
				_ = value
			}
		}
	}
	if value.PrefixOpRemoves != nil {
		for seq_i, seq_v := range value.PrefixOpRemoves {
			pseudoEncoder := &encoder.PrefixOpRemoves_subencoder[seq_i]
			pseudoValue := struct {
				PrefixOpRemoves *PrefixOpRemove
			}{
				PrefixOpRemoves: seq_v,
			}
			{
				encoder := pseudoEncoder
				value := &pseudoValue
				if value.PrefixOpRemoves != nil {
					buf[pos] = 253
					binary.BigEndian.PutUint16(buf[pos+1:], uint16(306))
					pos += 3
					pos += uint(enc.TLNum(encoder.PrefixOpRemoves_encoder.Length).EncodeInto(buf[pos:]))
					if encoder.PrefixOpRemoves_encoder.Length > 0 {
						encoder.PrefixOpRemoves_encoder.EncodeInto(value.PrefixOpRemoves, buf[pos:])
						pos += encoder.PrefixOpRemoves_encoder.Length
					}
				}
				_ = encoder
				_ = value
			}
		}
	}
}

func (encoder *PrefixOpListEncoder) Encode(value *PrefixOpList) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *PrefixOpListParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*PrefixOpList, error) {

	var handled_ExitRouter bool = false
	var handled_PrefixOpReset bool = false
	var handled_PrefixOpAdds bool = false
	var handled_PrefixOpRemoves bool = false

	progress := -1
	_ = progress

	value := &PrefixOpList{}
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
		if handled := false; true {
			switch typ {
			case 204:
				if true {
					handled = true
					handled_ExitRouter = true
					value.ExitRouter, err = context.ExitRouter_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			case 302:
				if true {
					handled = true
					handled_PrefixOpReset = true
					value.PrefixOpReset = true
					err = reader.Skip(int(l))
				}
			case 304:
				if true {
					handled = true
					handled_PrefixOpAdds = true
					if value.PrefixOpAdds == nil {
						value.PrefixOpAdds = make([]*PrefixOpAdd, 0)
					}
					{
						pseudoValue := struct {
							PrefixOpAdds *PrefixOpAdd
						}{}
						{
							value := &pseudoValue
							value.PrefixOpAdds, err = context.PrefixOpAdds_context.Parse(reader.Delegate(int(l)), ignoreCritical)
							_ = value
						}
						value.PrefixOpAdds = append(value.PrefixOpAdds, pseudoValue.PrefixOpAdds)
					}
					progress--
				}
			case 306:
				if true {
					handled = true
					handled_PrefixOpRemoves = true
					if value.PrefixOpRemoves == nil {
						value.PrefixOpRemoves = make([]*PrefixOpRemove, 0)
					}
					{
						pseudoValue := struct {
							PrefixOpRemoves *PrefixOpRemove
						}{}
						{
							value := &pseudoValue
							value.PrefixOpRemoves, err = context.PrefixOpRemoves_context.Parse(reader.Delegate(int(l)), ignoreCritical)
							_ = value
						}
						value.PrefixOpRemoves = append(value.PrefixOpRemoves, pseudoValue.PrefixOpRemoves)
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

	if !handled_ExitRouter && err == nil {
		value.ExitRouter = nil
	}
	if !handled_PrefixOpReset && err == nil {
		value.PrefixOpReset = false
	}
	if !handled_PrefixOpAdds && err == nil {
		// sequence - skip
	}
	if !handled_PrefixOpRemoves && err == nil {
		// sequence - skip
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *PrefixOpList) Encode() enc.Wire {
	encoder := PrefixOpListEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *PrefixOpList) Bytes() []byte {
	return value.Encode().Join()
}

func ParsePrefixOpList(reader enc.WireView, ignoreCritical bool) (*PrefixOpList, error) {
	context := PrefixOpListParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type PrefixOpAddEncoder struct {
	Length uint

	Name_length uint
}

type PrefixOpAddParsingContext struct {
}

func (encoder *PrefixOpAddEncoder) Init(value *PrefixOpAdd) {
	if value.Name != nil {
		encoder.Name_length = 0
		for _, c := range value.Name {
			encoder.Name_length += uint(c.EncodingLength())
		}
	}

	l := uint(0)
	if value.Name != nil {
		l += 1
		l += uint(enc.TLNum(encoder.Name_length).EncodingLength())
		l += encoder.Name_length
	}
	l += 1
	l += uint(1 + enc.Nat(value.Cost).EncodingLength())
	encoder.Length = l

}

func (context *PrefixOpAddParsingContext) Init() {

}

func (encoder *PrefixOpAddEncoder) EncodeInto(value *PrefixOpAdd, buf []byte) {

	pos := uint(0)

	if value.Name != nil {
		buf[pos] = byte(7)
		pos += 1
		pos += uint(enc.TLNum(encoder.Name_length).EncodeInto(buf[pos:]))
		for _, c := range value.Name {
			pos += uint(c.EncodeInto(buf[pos:]))
		}
	}
	buf[pos] = byte(208)
	pos += 1

	buf[pos] = byte(enc.Nat(value.Cost).EncodeInto(buf[pos+1:]))
	pos += uint(1 + buf[pos])
}

func (encoder *PrefixOpAddEncoder) Encode(value *PrefixOpAdd) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *PrefixOpAddParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*PrefixOpAdd, error) {

	var handled_Name bool = false
	var handled_Cost bool = false

	progress := -1
	_ = progress

	value := &PrefixOpAdd{}
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
		if handled := false; true {
			switch typ {
			case 7:
				if true {
					handled = true
					handled_Name = true
					delegate := reader.Delegate(int(l))
					value.Name, err = delegate.ReadName()
				}
			case 208:
				if true {
					handled = true
					handled_Cost = true
					value.Cost = uint64(0)
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
							value.Cost = uint64(value.Cost<<8) | uint64(x)
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

	if !handled_Name && err == nil {
		value.Name = nil
	}
	if !handled_Cost && err == nil {
		err = enc.ErrSkipRequired{Name: "Cost", TypeNum: 208}
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *PrefixOpAdd) Encode() enc.Wire {
	encoder := PrefixOpAddEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *PrefixOpAdd) Bytes() []byte {
	return value.Encode().Join()
}

func ParsePrefixOpAdd(reader enc.WireView, ignoreCritical bool) (*PrefixOpAdd, error) {
	context := PrefixOpAddParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type PrefixOpRemoveEncoder struct {
	Length uint

	Name_length uint
}

type PrefixOpRemoveParsingContext struct {
}

func (encoder *PrefixOpRemoveEncoder) Init(value *PrefixOpRemove) {
	if value.Name != nil {
		encoder.Name_length = 0
		for _, c := range value.Name {
			encoder.Name_length += uint(c.EncodingLength())
		}
	}

	l := uint(0)
	if value.Name != nil {
		l += 1
		l += uint(enc.TLNum(encoder.Name_length).EncodingLength())
		l += encoder.Name_length
	}
	encoder.Length = l

}

func (context *PrefixOpRemoveParsingContext) Init() {

}

func (encoder *PrefixOpRemoveEncoder) EncodeInto(value *PrefixOpRemove, buf []byte) {

	pos := uint(0)

	if value.Name != nil {
		buf[pos] = byte(7)
		pos += 1
		pos += uint(enc.TLNum(encoder.Name_length).EncodeInto(buf[pos:]))
		for _, c := range value.Name {
			pos += uint(c.EncodeInto(buf[pos:]))
		}
	}
}

func (encoder *PrefixOpRemoveEncoder) Encode(value *PrefixOpRemove) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *PrefixOpRemoveParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*PrefixOpRemove, error) {

	var handled_Name bool = false

	progress := -1
	_ = progress

	value := &PrefixOpRemove{}
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
		if handled := false; true {
			switch typ {
			case 7:
				if true {
					handled = true
					handled_Name = true
					delegate := reader.Delegate(int(l))
					value.Name, err = delegate.ReadName()
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

	if !handled_Name && err == nil {
		value.Name = nil
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *PrefixOpRemove) Encode() enc.Wire {
	encoder := PrefixOpRemoveEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *PrefixOpRemove) Bytes() []byte {
	return value.Encode().Join()
}

func ParsePrefixOpRemove(reader enc.WireView, ignoreCritical bool) (*PrefixOpRemove, error) {
	context := PrefixOpRemoveParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}

type StatusEncoder struct {
	Length uint

	NetworkName_encoder DestinationEncoder
	RouterName_encoder  DestinationEncoder
}

type StatusParsingContext struct {
	NetworkName_context DestinationParsingContext
	RouterName_context  DestinationParsingContext
}

func (encoder *StatusEncoder) Init(value *Status) {

	if value.NetworkName != nil {
		encoder.NetworkName_encoder.Init(value.NetworkName)
	}
	if value.RouterName != nil {
		encoder.RouterName_encoder.Init(value.RouterName)
	}

	l := uint(0)
	l += 3
	l += uint(enc.TLNum(len(value.Version)).EncodingLength())
	l += uint(len(value.Version))
	if value.NetworkName != nil {
		l += 3
		l += uint(enc.TLNum(encoder.NetworkName_encoder.Length).EncodingLength())
		l += encoder.NetworkName_encoder.Length
	}
	if value.RouterName != nil {
		l += 3
		l += uint(enc.TLNum(encoder.RouterName_encoder.Length).EncodingLength())
		l += encoder.RouterName_encoder.Length
	}
	l += 3
	l += uint(1 + enc.Nat(value.NRibEntries).EncodingLength())
	l += 3
	l += uint(1 + enc.Nat(value.NNeighbors).EncodingLength())
	l += 3
	l += uint(1 + enc.Nat(value.NFibEntries).EncodingLength())
	encoder.Length = l

}

func (context *StatusParsingContext) Init() {

	context.NetworkName_context.Init()
	context.RouterName_context.Init()

}

func (encoder *StatusEncoder) EncodeInto(value *Status, buf []byte) {

	pos := uint(0)

	buf[pos] = 253
	binary.BigEndian.PutUint16(buf[pos+1:], uint16(401))
	pos += 3
	pos += uint(enc.TLNum(len(value.Version)).EncodeInto(buf[pos:]))
	copy(buf[pos:], value.Version)
	pos += uint(len(value.Version))
	if value.NetworkName != nil {
		buf[pos] = 253
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(403))
		pos += 3
		pos += uint(enc.TLNum(encoder.NetworkName_encoder.Length).EncodeInto(buf[pos:]))
		if encoder.NetworkName_encoder.Length > 0 {
			encoder.NetworkName_encoder.EncodeInto(value.NetworkName, buf[pos:])
			pos += encoder.NetworkName_encoder.Length
		}
	}
	if value.RouterName != nil {
		buf[pos] = 253
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(405))
		pos += 3
		pos += uint(enc.TLNum(encoder.RouterName_encoder.Length).EncodeInto(buf[pos:]))
		if encoder.RouterName_encoder.Length > 0 {
			encoder.RouterName_encoder.EncodeInto(value.RouterName, buf[pos:])
			pos += encoder.RouterName_encoder.Length
		}
	}
	buf[pos] = 253
	binary.BigEndian.PutUint16(buf[pos+1:], uint16(407))
	pos += 3

	buf[pos] = byte(enc.Nat(value.NRibEntries).EncodeInto(buf[pos+1:]))
	pos += uint(1 + buf[pos])
	buf[pos] = 253
	binary.BigEndian.PutUint16(buf[pos+1:], uint16(409))
	pos += 3

	buf[pos] = byte(enc.Nat(value.NNeighbors).EncodeInto(buf[pos+1:]))
	pos += uint(1 + buf[pos])
	buf[pos] = 253
	binary.BigEndian.PutUint16(buf[pos+1:], uint16(411))
	pos += 3

	buf[pos] = byte(enc.Nat(value.NFibEntries).EncodeInto(buf[pos+1:]))
	pos += uint(1 + buf[pos])
}

func (encoder *StatusEncoder) Encode(value *Status) enc.Wire {

	wire := make(enc.Wire, 1)
	wire[0] = make([]byte, encoder.Length)
	buf := wire[0]
	encoder.EncodeInto(value, buf)

	return wire
}

func (context *StatusParsingContext) Parse(reader enc.WireView, ignoreCritical bool) (*Status, error) {

	var handled_Version bool = false
	var handled_NetworkName bool = false
	var handled_RouterName bool = false
	var handled_NRibEntries bool = false
	var handled_NNeighbors bool = false
	var handled_NFibEntries bool = false

	progress := -1
	_ = progress

	value := &Status{}
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
		if handled := false; true {
			switch typ {
			case 401:
				if true {
					handled = true
					handled_Version = true
					{
						var builder strings.Builder
						_, err = reader.CopyN(&builder, int(l))
						if err == nil {
							value.Version = builder.String()
						}
					}
				}
			case 403:
				if true {
					handled = true
					handled_NetworkName = true
					value.NetworkName, err = context.NetworkName_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			case 405:
				if true {
					handled = true
					handled_RouterName = true
					value.RouterName, err = context.RouterName_context.Parse(reader.Delegate(int(l)), ignoreCritical)
				}
			case 407:
				if true {
					handled = true
					handled_NRibEntries = true
					value.NRibEntries = uint64(0)
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
							value.NRibEntries = uint64(value.NRibEntries<<8) | uint64(x)
						}
					}
				}
			case 409:
				if true {
					handled = true
					handled_NNeighbors = true
					value.NNeighbors = uint64(0)
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
							value.NNeighbors = uint64(value.NNeighbors<<8) | uint64(x)
						}
					}
				}
			case 411:
				if true {
					handled = true
					handled_NFibEntries = true
					value.NFibEntries = uint64(0)
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
							value.NFibEntries = uint64(value.NFibEntries<<8) | uint64(x)
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

	if !handled_Version && err == nil {
		err = enc.ErrSkipRequired{Name: "Version", TypeNum: 401}
	}
	if !handled_NetworkName && err == nil {
		value.NetworkName = nil
	}
	if !handled_RouterName && err == nil {
		value.RouterName = nil
	}
	if !handled_NRibEntries && err == nil {
		err = enc.ErrSkipRequired{Name: "NRibEntries", TypeNum: 407}
	}
	if !handled_NNeighbors && err == nil {
		err = enc.ErrSkipRequired{Name: "NNeighbors", TypeNum: 409}
	}
	if !handled_NFibEntries && err == nil {
		err = enc.ErrSkipRequired{Name: "NFibEntries", TypeNum: 411}
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (value *Status) Encode() enc.Wire {
	encoder := StatusEncoder{}
	encoder.Init(value)
	return encoder.Encode(value)
}

func (value *Status) Bytes() []byte {
	return value.Encode().Join()
}

func ParseStatus(reader enc.WireView, ignoreCritical bool) (*Status, error) {
	context := StatusParsingContext{}
	context.Init()
	return context.Parse(reader, ignoreCritical)
}
