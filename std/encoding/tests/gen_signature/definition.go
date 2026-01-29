//go:generate gondn_tlv_gen
package gen_signature

import (
	"bytes"
	"crypto/sha256"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// +tlv-model:nocopy,private,ordered
type T1 struct {
	//+field:natural
	H1 uint64 `tlv:"0x01"`
	//+field:offsetMarker
	sigCoverStart enc.PlaceHolder
	//+field:natural:optional
	H2 optional.Optional[uint64] `tlv:"0x02"`
	//+field:wire
	C enc.Wire `tlv:"0x03"`
	//+field:signature:sigCoverStart:sigCovered
	Sig enc.Wire `tlv:"0x04"`

	//+field:procedureArgument:enc.Wire
	sigCovered enc.PlaceHolder

	//+field:natural:optional
	H3 optional.Optional[uint64] `tlv:"0x06"`
}

// (AI GENERATED DESCRIPTION): Encodes a T1 packet, inserting the provided signature value into the encoded wire and updating its length field, and returns the full encoded wire along with the sub‑wire that the signature covers.
func (v *T1) Encode(estLen uint, value []byte) (enc.Wire, enc.Wire) {
	encoder := T1Encoder{
		Sig_estLen: estLen,
	}
	encoder.Init(v)
	wire := encoder.Encode(v)
	// Compute signature
	if encoder.Sig_wireIdx >= 0 {
		wire[encoder.Sig_wireIdx] = value
		// Fix length, assuming len(value) <= estLen < 253
		buf := wire[encoder.Sig_wireIdx-1]
		buf[len(buf)-1] = byte(len(value))
	}

	return wire, encoder.sigCovered
}

// (AI GENERATED DESCRIPTION): Parses a T1 packet from the given WireView, returning the parsed T1 object and the signature‑covered portion of the packet.
func ReadT1(reader enc.WireView) (*T1, enc.Wire, error) {
	context := T1ParsingContext{}
	context.Init()
	ret, err := context.Parse(reader, false)
	if err != nil {
		return nil, nil, err
	}
	return ret, context.sigCovered, nil
}

// +tlv-model:nocopy,private,ordered
type T2 struct {
	//+field:interestName:sigCovered
	Name enc.Name `tlv:"0x01"`
	//+field:offsetMarker
	sigCoverStart enc.PlaceHolder
	//+field:offsetMarker
	digestCoverStart enc.PlaceHolder
	//+field:wire
	C enc.Wire `tlv:"0x03"`
	//+field:signature:sigCoverStart:sigCovered
	Sig enc.Wire `tlv:"0x04"`

	//+field:offsetMarker
	digestCoverEnd enc.PlaceHolder
	//+field:procedureArgument:enc.Wire
	sigCovered enc.PlaceHolder
}

// (AI GENERATED DESCRIPTION): Encodes a T2 object into its binary wire format, inserting the supplied signature (if any) and, when requested, computing a SHA‑256 digest over the designated packet portion and embedding that digest into the name component.
func (v *T2) Encode(estLen uint, value []byte, needDigest bool) (enc.Wire, enc.Wire) {
	if v.Name == nil {
		return nil, nil
	}
	encoder := T2Encoder{
		Sig_estLen:      estLen,
		Name_needDigest: needDigest,
	}
	encoder.Init(v)
	wire := encoder.Encode(v)
	// Compute signature
	if encoder.Sig_wireIdx >= 0 {
		wire[encoder.Sig_wireIdx] = value
		// Fix length, assuming len(value) <= estLen < 253
		buf := wire[encoder.Sig_wireIdx-1]
		buf[len(buf)-1] = byte(len(value))
	}
	// Compute digest
	if needDigest {
		buf := wire[encoder.Name_wireIdx]
		digestBuf := buf[encoder.Name_pos : encoder.Name_pos+32]
		v.Name[len(v.Name)-1].Val = digestBuf

		digestCovered := enc.Wire(nil)
		if encoder.digestCoverStart_wireIdx == encoder.digestCoverEnd_wireIdx {
			buf := wire[encoder.digestCoverStart_wireIdx]
			coveredPart := buf[encoder.digestCoverStart_pos:encoder.digestCoverEnd_pos]
			digestCovered = enc.Wire{coveredPart}
		} else {
			coverStart := wire[encoder.digestCoverStart_wireIdx][encoder.digestCoverStart_pos:]
			digestCovered = append(digestCovered, coverStart)
			for i := encoder.digestCoverStart_wireIdx + 1; i < encoder.digestCoverEnd_wireIdx; i++ {
				digestCovered = append(digestCovered, wire[i])
			}
			if encoder.digestCoverEnd_pos > 0 { // Actually always false
				coverEnd := wire[encoder.digestCoverEnd_wireIdx][:encoder.digestCoverEnd_pos]
				digestCovered = append(digestCovered, coverEnd)
			}
		}

		h := sha256.New()
		for _, buf := range digestCovered {
			_, err := h.Write(buf)
			if err != nil {
				return nil, nil
			}
		}
		copy(digestBuf, h.Sum(nil))
	}

	return wire, encoder.sigCovered
}

// (AI GENERATED DESCRIPTION): Parses a T2 packet from a wire view, optionally verifies that its last name component is the correct SHA‑256 digest of the signed data, and returns the parsed packet together with the signed portion of the packet.
func ReadT2(reader enc.WireView, digestRequired bool) (*T2, enc.Wire, error) {
	context := T2ParsingContext{}
	context.Init()
	ret, err := context.Parse(reader, false)
	if err != nil {
		return nil, nil, err
	}

	if digestRequired {
		if len(ret.Name) == 0 || ret.Name[len(ret.Name)-1].Typ != enc.TypeParametersSha256DigestComponent {
			return nil, nil, enc.ErrIncorrectDigest
		}
		digestCovered := reader.Range(context.digestCoverStart, context.digestCoverEnd)
		h := sha256.New()
		for _, buf := range digestCovered {
			_, err := h.Write(buf)
			if err != nil {
				return nil, nil, enc.ErrUnexpected{Err: err}
			}
		}
		digestBuf := h.Sum(nil)
		if !bytes.Equal(ret.Name[len(ret.Name)-1].Val, digestBuf) {
			return nil, nil, enc.ErrIncorrectDigest
		}
	}

	return ret, context.sigCovered, nil
}
