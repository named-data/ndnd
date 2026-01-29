package spec_2022

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

const TimeFmt = "20060102T150405" // ISO 8601 time format

// (AI GENERATED DESCRIPTION): Checks at compile time that the Data and Interest types implement the ndn.Signature, ndn.Data, and ndn.Interest interfaces.
func _() {
	// Trait for Signature of Data
	var _ ndn.Signature = &Data{}
	// Trait for Signature of Interest
	var _ ndn.Signature = &Interest{}
	// Trait for Data of Data
	var _ ndn.Data = &Data{}
	// Trait for Interest of Interest
	var _ ndn.Interest = &Interest{}
}

type Spec struct{}

// (AI GENERATED DESCRIPTION): Returns the signature type of the Data packet, defaulting to ndn.SignatureNone when SignatureInfo is nil.
func (d *Data) SigType() ndn.SigType {
	if d.SignatureInfo == nil {
		return ndn.SignatureNone
	} else {
		return ndn.SigType(d.SignatureInfo.SignatureType)
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the name of the key used to sign the data packet, returning the key‑locator’s name or nil when the signature info or key locator is absent.
func (d *Data) KeyName() enc.Name {
	if d.SignatureInfo == nil || d.SignatureInfo.KeyLocator == nil {
		return nil
	} else {
		return d.SignatureInfo.KeyLocator.Name
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the signature nonce attached to the Data packet, returning nil if no nonce is present.
func (d *Data) SigNonce() []byte {
	return nil
}

// (AI GENERATED DESCRIPTION): Returns the signature timestamp of the Data packet (currently unimplemented and returns nil).
func (d *Data) SigTime() *time.Time {
	return nil
}

// (AI GENERATED DESCRIPTION): Sets the Data packet’s SignatureInfo.SignatureTime to the given time (converted to a millisecond duration) or clears the field if the argument is nil.
func (d *Data) SetSigTime(t *time.Time) error {
	if d.SignatureInfo == nil {
		d.SignatureInfo = &SignatureInfo{}
	}
	if t == nil {
		d.SignatureInfo.SignatureTime.Unset()
	} else {
		d.SignatureInfo.SignatureTime = optional.Some(time.Duration(t.UnixMilli()) * time.Millisecond)
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Retrieves the sequence number associated with the packet’s signature (returning nil if the field is not set).
func (d *Data) SigSeqNum() *uint64 {
	return nil
}

// (AI GENERATED DESCRIPTION): Retrieves the optional “NotBefore” and “NotAfter” timestamps from a Data packet’s SignatureInfo validity period, returning them as `optional.Optional[time.Time]` values when present.
func (d *Data) Validity() (notBefore, notAfter optional.Optional[time.Time]) {
	if d.SignatureInfo != nil && d.SignatureInfo.ValidityPeriod != nil {
		nbVal, err := time.Parse(TimeFmt, d.SignatureInfo.ValidityPeriod.NotBefore)
		if err != nil {
			return
		}
		naVal, err := time.Parse(TimeFmt, d.SignatureInfo.ValidityPeriod.NotAfter)
		if err != nil {
			return
		}
		return optional.Some(nbVal), optional.Some(naVal)
	}
	return
}

// (AI GENERATED DESCRIPTION): Returns the Data packet’s signature value as a byte slice, or nil if no signature is present.
func (d *Data) SigValue() []byte {
	if d.SignatureValue == nil {
		return nil
	} else {
		return d.SignatureValue.Join()
	}
}

// (AI GENERATED DESCRIPTION): Returns the Data packet itself as its own signature, allowing the Data struct to satisfy the ndn.Signature interface.
func (d *Data) Signature() ndn.Signature {
	return d
}

// (AI GENERATED DESCRIPTION): Returns the name (enc.Name) of the Data packet.
func (d *Data) Name() enc.Name {
	return d.NameV
}

// (AI GENERATED DESCRIPTION): Returns the Data packet's `ContentType` from its `MetaInfo`, if present, wrapped as an `optional.Optional[ndn.ContentType]`.
func (d *Data) ContentType() (val optional.Optional[ndn.ContentType]) {
	if d.MetaInfo != nil {
		return optional.CastInt[uint64, ndn.ContentType](d.MetaInfo.ContentType)
	}
	return val
}

// (AI GENERATED DESCRIPTION): Returns the Data packet’s freshness period from MetaInfo if present; otherwise returns an empty optional.
func (d *Data) Freshness() (val optional.Optional[time.Duration]) {
	if d.MetaInfo != nil {
		return d.MetaInfo.FreshnessPeriod
	}
	return val
}

// (AI GENERATED DESCRIPTION): Returns the MetaInfo’s FinalBlockID component as an optional, yielding a parsed `enc.Component` if present and valid, otherwise an empty optional.
func (d *Data) FinalBlockID() (val optional.Optional[enc.Component]) {
	if d.MetaInfo != nil && d.MetaInfo.FinalBlockID != nil {
		reader := enc.NewBufferView(d.MetaInfo.FinalBlockID)
		if ret, err := reader.ReadComponent(); err == nil {
			return optional.Some(ret)
		}
	}
	return val
}

// (AI GENERATED DESCRIPTION): Returns the Data packet’s content payload as a wire‑encoded value.
func (d *Data) Content() enc.Wire {
	return d.ContentV
}

// (AI GENERATED DESCRIPTION): Returns the wire representation of the Data packet in the cross‑schema format.
func (d *Data) CrossSchema() enc.Wire {
	return d.CrossSchemaV
}

// (AI GENERATED DESCRIPTION): Returns the signature type of the Interest packet, defaulting to `SignatureNone` when no signature information is present.
func (t *Interest) SigType() ndn.SigType {
	if t.SignatureInfo == nil {
		return ndn.SignatureNone
	} else {
		return ndn.SigType(t.SignatureInfo.SignatureType)
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the key name stored in the Interest’s SignatureInfo.KeyLocator, returning nil if the SignatureInfo or KeyLocator is absent.
func (t *Interest) KeyName() enc.Name {
	if t.SignatureInfo == nil || t.SignatureInfo.KeyLocator == nil {
		return nil
	} else {
		return t.SignatureInfo.KeyLocator.Name
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the signature nonce stored in the Interest’s SignatureInfo, returning `nil` if no nonce is present.
func (t *Interest) SigNonce() []byte {
	if t.SignatureInfo != nil {
		return t.SignatureInfo.SignatureNonce
	} else {
		return nil
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the signature timestamp of an Interest, returning it as a `*time.Time` when set, or `nil` if no signature time is present.
func (t *Interest) SigTime() *time.Time {
	if t.SignatureInfo != nil && t.SignatureInfo.SignatureTime.IsSet() {
		return utils.IdPtr(time.UnixMilli(t.SignatureInfo.SignatureTime.Unwrap().Milliseconds()))
	} else {
		return nil
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the signature sequence number from an Interest's SignatureInfo when set, returning a pointer to it; otherwise returns nil.
func (t *Interest) SigSeqNum() *uint64 {
	if t.SignatureInfo != nil && t.SignatureInfo.SignatureSeqNum.IsSet() {
		return utils.IdPtr(t.SignatureInfo.SignatureSeqNum.Unwrap())
	} else {
		return nil
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the optional notBefore and notAfter timestamps of the Interest packet, returning unset optional values if no validity period is set.
func (t *Interest) Validity() (notBefore, notAfter optional.Optional[time.Time]) {
	return
}

// (AI GENERATED DESCRIPTION): Returns the concatenated raw signature value of the Interest packet as a byte slice.
func (t *Interest) SigValue() []byte {
	return t.SignatureValue.Join()
}

// (AI GENERATED DESCRIPTION): Returns the Interest packet itself as its signature (the Interest implements the ndn.Signature interface).
func (t *Interest) Signature() ndn.Signature {
	return t
}

// (AI GENERATED DESCRIPTION): Returns the Interest packet’s name as an enc.Name value.
func (t *Interest) Name() enc.Name {
	return t.NameV
}

// (AI GENERATED DESCRIPTION): Returns whether the CanBePrefix flag is set on this Interest packet, indicating that it may be satisfied by Data packets whose name is a prefix of the Interest.
func (t *Interest) CanBePrefix() bool {
	return t.CanBePrefixV
}

// (AI GENERATED DESCRIPTION): Returns whether the MustBeFresh flag is set for this Interest packet.
func (t *Interest) MustBeFresh() bool {
	return t.MustBeFreshV
}

// (AI GENERATED DESCRIPTION): Retrieves the slice of forwarding‑hint names from the Interest packet, returning nil if no forwarding hint is set.
func (t *Interest) ForwardingHint() []enc.Name {
	if t.ForwardingHintV == nil {
		return nil
	}
	return t.ForwardingHintV.Names
}

// (AI GENERATED DESCRIPTION): Retrieves the optional Nonce value from the Interest packet.
func (t *Interest) Nonce() optional.Optional[uint32] {
	return t.NonceV
}

// (AI GENERATED DESCRIPTION): Returns the optional lifetime duration of this Interest packet.
func (t *Interest) Lifetime() optional.Optional[time.Duration] {
	return t.InterestLifetimeV
}

// (AI GENERATED DESCRIPTION): Retrieves the hop limit of an Interest, returning it as a `*uint` or `nil` if the hop limit is not set.
func (t *Interest) HopLimit() *uint {
	if t.HopLimitV == nil {
		return nil
	} else {
		return utils.IdPtr(uint(*t.HopLimitV))
	}
}

// (AI GENERATED DESCRIPTION): Returns the ApplicationParameters field of the Interest packet.
func (t *Interest) AppParam() enc.Wire {
	return t.ApplicationParameters
}

// MakeData encodes an NDN Data.
func (Spec) MakeData(name enc.Name, config *ndn.DataConfig, content enc.Wire, signer ndn.Signer) (*ndn.EncodedData, error) {
	// Create Data packet.
	if name == nil {
		return nil, ndn.ErrInvalidValue{Item: "Data.Name", Value: nil}
	}
	if config == nil {
		return nil, ndn.ErrInvalidValue{Item: "Data.DataConfig", Value: nil}
	}
	finalBlock := []byte(nil)
	if fbid, ok := config.FinalBlockID.Get(); ok {
		finalBlock = fbid.Bytes()
	}
	data := &Data{
		NameV: name,
		MetaInfo: &MetaInfo{
			ContentType:     optional.CastInt[ndn.ContentType, uint64](config.ContentType),
			FreshnessPeriod: config.Freshness,
			FinalBlockID:    finalBlock,
		},
		ContentV:       content,
		SignatureInfo:  nil,
		SignatureValue: nil,
		CrossSchemaV:   config.CrossSchema,
	}
	packet := &Packet{
		Data: data,
	}

	// Fill-in SignatureInfo.
	estSigLen := 0
	if signer != nil && signer.Type() != ndn.SignatureNone {
		estSigLen = int(signer.EstimateSize())

		data.SignatureInfo = &SignatureInfo{
			SignatureType: uint64(signer.Type()),
		}

		if key := signer.KeyLocator(); key != nil {
			data.SignatureInfo.KeyLocator = &KeyLocator{Name: key}
		}

		if config.SigNotBefore.IsSet() && config.SigNotAfter.IsSet() {
			data.SignatureInfo.ValidityPeriod = &ValidityPeriod{
				NotBefore: config.SigNotBefore.Unwrap().UTC().Format(TimeFmt),
				NotAfter:  config.SigNotAfter.Unwrap().UTC().Format(TimeFmt),
			}
		}
	}

	// Encode packet.
	encoder := PacketEncoder{
		Data_encoder: DataEncoder{
			SignatureValue_estLen: uint(estSigLen),
		},
	}

	encoder.Init(packet)
	wire := encoder.Encode(packet)
	if wire == nil {
		return nil, ndn.ErrFailedToEncode
	}
	sigCovered := enc.Wire(nil)
	if estSigLen > 0 {
		// Compute signature
		sigCovered = encoder.Data_encoder.sigCovered

		// Since PacketEncoder only adds a TL, Data_encoder.SignatureValue_wireIdx is still valid
		sigVal, err := signer.Sign(sigCovered)
		if err != nil {
			return nil, err
		}

		if len(sigVal) > estSigLen {
			return nil, ndn.ErrNotSupported{Item: "Signature value cannot be longer than estimated length"}
		}
		wire[encoder.Data_encoder.SignatureValue_wireIdx] = sigVal

		// Fix SignatureValue length
		// This does not handle the case where the signature value is so much shorter than
		// the estimated length that the length field needs to be shrunk.
		// The signer needs to provide a reasonable estimate, hopefully exact.
		buf := wire[encoder.Data_encoder.SignatureValue_wireIdx-1]
		buf[len(buf)-1] = byte(len(sigVal))
		shrink := estSigLen - len(sigVal)
		wire[0] = enc.ShrinkLength(wire[0], shrink)
	}
	return &ndn.EncodedData{
		Wire:       wire,
		SigCovered: sigCovered,
		Config:     config,
	}, nil
}

// ReadData parses a Data from the reader.
// Precondition: reader contains only one TLV.
func (Spec) ReadData(reader enc.WireView) (ndn.Data, enc.Wire, error) {
	context := PacketParsingContext{}
	context.Init()
	ret, err := context.Parse(reader, false)
	if err != nil {
		return nil, nil, err
	}
	if ret.Data == nil {
		return nil, nil, ndn.ErrWrongType
	}
	if ret.Data.NameV == nil {
		return nil, nil, ndn.ErrInvalidValue{Item: "Data.Name", Value: nil}
	}
	return ret.Data, context.Data_context.sigCovered, nil
}

// MakeInterest encodes an NDN Interest.
func (Spec) MakeInterest(name enc.Name, config *ndn.InterestConfig, appParam enc.Wire, signer ndn.Signer) (*ndn.EncodedInterest, error) {
	// Create Interest packet.
	if name == nil {
		return nil, ndn.ErrInvalidValue{Item: "Interest.Name", Value: nil}
	}
	if config == nil {
		return nil, ndn.ErrInvalidValue{Item: "Interest.DataConfig", Value: nil}
	}
	forwardingHint := (*Links)(nil)
	if config.ForwardingHint != nil {
		forwardingHint = &Links{
			Names: config.ForwardingHint,
		}
	}
	interest := &Interest{
		NameV:                 name,
		CanBePrefixV:          config.CanBePrefix,
		MustBeFreshV:          config.MustBeFresh,
		ForwardingHintV:       forwardingHint,
		NonceV:                config.Nonce,
		InterestLifetimeV:     config.Lifetime,
		HopLimitV:             config.HopLimit,
		ApplicationParameters: appParam,
		SignatureInfo:         nil,
		SignatureValue:        nil,
	}
	packet := &Packet{
		Interest: interest,
	}

	needDigest := appParam != nil
	estSigLen := 0

	// Fill-in SignatureInfo.
	if signer != nil && signer.Type() != ndn.SignatureNone {
		if !needDigest {
			return nil, ndn.ErrInvalidValue{Item: "Interest.ApplicationParameters", Value: nil}
		}

		estSigLen = int(signer.EstimateSize())

		interest.SignatureInfo = &SignatureInfo{
			SignatureType:   uint64(signer.Type()),
			SignatureNonce:  config.SigNonce,
			SignatureTime:   config.SigTime,
			SignatureSeqNum: config.SigSeqNo,
		}

		if key := signer.KeyLocator(); key != nil {
			interest.SignatureInfo.KeyLocator = &KeyLocator{Name: key}
		}
	}

	// Encode packet.
	encoder := PacketEncoder{
		Interest_encoder: InterestEncoder{
			SignatureValue_estLen: uint(estSigLen),
			NameV_needDigest:      needDigest,
		},
	}
	ecdr := &encoder.Interest_encoder
	encoder.Init(packet)
	wire := encoder.Encode(packet)
	if wire == nil {
		return nil, ndn.ErrFailedToEncode
	}
	sigVal := []byte(nil)
	err := error(nil)
	sigCovered := enc.Wire(nil)
	if estSigLen > 0 {
		// Compute signature
		sigCovered = ecdr.sigCovered
		if ecdr.SignatureValue_wireIdx < 0 {
			return nil, enc.ErrUnexpected{Err: errors.New("SignatureValue is not correctly set")}
		}

		// Since PacketEncoder only adds a TL, Interest_encoder.SignatureValue_wireIdx is still valid
		sigVal, err = signer.Sign(sigCovered)
		if err != nil {
			return nil, err
		}

		if uint(len(sigVal)) > ecdr.SignatureValue_estLen {
			return nil, ndn.ErrNotSupported{Item: "Signature value cannot be longer than estimated length"}
		}

		// Fix SignatureValue length
		wire[ecdr.SignatureValue_wireIdx] = sigVal
		buf := wire[ecdr.SignatureValue_wireIdx-1]
		buf[len(buf)-1] = byte(len(sigVal))

		// Don't fix packet length for now, as it may cause trouble
	}
	finalName := packet.Interest.NameV
	if needDigest {
		// Compute digest
		// assert ecdr.NameV_wireIdx == 0
		buf := wire[0]
		_, s1 := enc.ParseTLNum(buf)
		_, s2 := enc.ParseTLNum(buf[s1:])
		// Add the offset by Interest TL
		digestPos := ecdr.NameV_pos + uint(s1+s2)
		digestBuf := buf[digestPos : digestPos+32]
		// Set the digest of final name
		finalName[len(finalName)-1].Val = digestBuf
		// Due to no copy, digest coveres AppParam type(1B) + len + wire[1:]
		appParamLen := enc.TLNum(appParam.Length()).EncodingLength()
		digestCovered := wire[1:]
		// Compute sha256 hash
		h := sha256.New()
		h.Write(wire[0][len(wire[0])-appParamLen-1:])
		for _, buf := range digestCovered {
			_, err = h.Write(buf)
			if err != nil {
				return nil, enc.ErrUnexpected{Err: err}
			}
		}
		copy(digestBuf, h.Sum(nil))
	}

	// Fix packet length
	shrink := estSigLen - len(sigVal)
	if shrink > 0 {
		wire[0] = enc.ShrinkLength(wire[0], shrink)
	} else if shrink < 0 {
		return nil, ndn.ErrNotSupported{Item: "Too long signature value is not supported"}
	}

	return &ndn.EncodedInterest{
		Wire:       wire,
		SigCovered: sigCovered,
		FinalName:  finalName,
		Config:     config,
	}, nil
}

// (AI GENERATED DESCRIPTION): Validates an Interest packet by ensuring it has a name, that a signature digest is present when ApplicationParameters are included, and that the SHA‑256 digest component of the name matches the hash of the covered data.
func checkInterest(val *Interest, context *InterestParsingContext) error {
	if val.NameV == nil {
		return ndn.ErrInvalidValue{Item: "Interest.Name", Value: nil}
	}
	if val.SignatureValue != nil && val.ApplicationParameters == nil {
		return enc.ErrIncorrectDigest
	}
	if val.ApplicationParameters != nil {
		// Check digest
		name := val.NameV
		if len(name) == 0 || name.At(-1).Typ != enc.TypeParametersSha256DigestComponent {
			return enc.ErrIncorrectDigest
		}
		digestCovered := context.digestCovered
		h := sha256.New()
		for _, buf := range digestCovered {
			_, err := h.Write(buf)
			if err != nil {
				return enc.ErrUnexpected{Err: err}
			}
		}
		digestBuf := h.Sum(nil)
		if !bytes.Equal(name.At(-1).Val, digestBuf) {
			return enc.ErrIncorrectDigest
		}
	}
	return nil
}

// ReadInterest parses an Interest from the reader.
// Precondition: reader contains only one TLV.
func (Spec) ReadInterest(reader enc.WireView) (ndn.Interest, enc.Wire, error) {
	context := PacketParsingContext{}
	context.Init()
	pkt, err := context.Parse(reader, false)
	if err != nil {
		return nil, nil, err
	}
	if pkt.Interest == nil {
		return nil, nil, ndn.ErrWrongType
	}

	err = checkInterest(pkt.Interest, &context.Interest_context)
	if err != nil {
		return nil, nil, err
	}

	return pkt.Interest, context.Interest_context.sigCovered, nil
}

// ReadPacket parses a packet from the reader.
//
//	Precondition: reader contains only one TLV.
//	Postcondition: exactly one of Interest, Data, or LpPacket is returned.
//
// If precondition is not met, then postcondition is not required to hold. But the call won't crash.
func ReadPacket(reader enc.WireView) (ret *Packet, context PacketParsingContext, err error) {
	context.Init()
	ret, err = context.Parse(reader, false)
	if err != nil {
		return
	}
	if ret.Data != nil {
		if ret.Data.NameV == nil {
			err = ndn.ErrInvalidValue{Item: "Data.Name", Value: nil}
			return
		}
	} else if ret.Interest != nil {
		err = checkInterest(ret.Interest, &context.Interest_context)
		if err != nil {
			return
		}
	} else if ret.LpPacket != nil {
		// As a client we shouldn't receive IDLE packets
		if ret.LpPacket.Fragment == nil {
			err = ndn.ErrInvalidValue{Item: "LpPacket.Fragment", Value: nil}
			return
		}
	} else {
		err = ndn.ErrWrongType
		return
	}
	return
}

// (AI GENERATED DESCRIPTION): Returns the wire representation of the signature‑covered portion of an Interest packet.
func (c InterestParsingContext) SigCovered() enc.Wire {
	return c.sigCovered
}

// (AI GENERATED DESCRIPTION): Returns the wire representation of the portion of the Data packet that is covered by the signature.
func (c DataParsingContext) SigCovered() enc.Wire {
	return c.sigCovered
}
