package signer

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

// GetSecret gets the key secret bits.
func GetSecret(key ndn.Signer) ([]byte, error) {
	// Unwrap context signer so downstream logic sees the concrete key type.
	if cs, ok := key.(*ContextSigner); ok && cs != nil {
		return GetSecret(cs.base)
	}
	switch key := key.(type) {
	case *eccSigner:
		return key.Secret()
	case *rsaSigner:
		return key.Secret()
	case *ed25519Signer:
		return key.Secret()
	default:
		return nil, ndn.ErrNotSupported{Item: "key type"}
	}
}

// MarshalSecret encodes a key secret to a signed NDN Data packet.
func MarshalSecret(key ndn.Signer) (enc.Wire, error) {
	// Get key name
	name := key.KeyName()
	if name == nil {
		return nil, ndn.ErrInvalidValue{Item: "key locator"}
	}

	// Get key secret bits
	sk, err := GetSecret(key)
	if err != nil {
		return nil, err
	} else if sk == nil {
		return nil, ndn.ErrInvalidValue{Item: "key secret"}
	}

	// Encode key data packet
	cfg := &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeSigningKey),
	}
	data, err := spec.Spec{}.MakeData(name, cfg, enc.Wire{sk}, key)
	if err != nil {
		return nil, err
	}

	return data.Wire, nil
}

// MarshalSecretToData encodes a key secret to a signed NDN Data packet.
func MarshalSecretToData(key ndn.Signer) (ndn.Data, error) {
	wire, err := MarshalSecret(key)
	if err != nil {
		return nil, err
	}
	data, _, err := spec.Spec{}.ReadData(enc.NewWireView(wire))
	return data, err
}

// UnmarshalSecret decodes a signed NDN Data packet to a key secret.
func UnmarshalSecret(data ndn.Data) (ndn.Signer, error) {
	// Check data content type
	if ctype, ok := data.ContentType().Get(); !ok || ctype != ndn.ContentTypeSigningKey {
		return nil, ndn.ErrInvalidValue{Item: "content type"}
	}

	// Check signature is present
	if data.Signature() == nil {
		return nil, ndn.ErrInvalidValue{Item: "signature"}
	}

	// Decode key secret bits
	wire := data.Content().Join()
	if len(wire) == 0 {
		return nil, ndn.ErrInvalidValue{Item: "content"}
	}

	// Check name
	name := data.Name()
	if len(name) < 2 || name[len(name)-2].String() != "KEY" {
		return nil, ndn.ErrInvalidValue{Item: "name", Value: name}
	}

	// Decode key secret depending on signature type
	switch data.Signature().SigType() {
	case ndn.SignatureSha256WithEcdsa:
		return ParseEcc(name, wire)
	case ndn.SignatureSha256WithRsa:
		return ParseRsa(name, wire)
	case ndn.SignatureEd25519:
		return ParseEd25519(name, wire)
	default:
		return nil, ndn.ErrNotSupported{Item: "signature type"}
	}
}
