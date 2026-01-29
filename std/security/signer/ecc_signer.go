package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// eccSigner is a signer that uses ECC key to sign packets.
type eccSigner struct {
	name   enc.Name
	key    *ecdsa.PrivateKey
	keyLen uint
}

// (AI GENERATED DESCRIPTION): Returns the signature type for an ECDSA signer, specifically SHA‑256 with ECDSA.
func (s *eccSigner) Type() ndn.SigType {
	return ndn.SignatureSha256WithEcdsa
}

// (AI GENERATED DESCRIPTION): Retrieves the enc.Name that identifies the ECC signer's key.
func (s *eccSigner) KeyName() enc.Name {
	return s.name
}

// (AI GENERATED DESCRIPTION): Returns the name of the key associated with the ECC signer.
func (s *eccSigner) KeyLocator() enc.Name {
	return s.name
}

// (AI GENERATED DESCRIPTION): Estimates the size, in bytes, of the ECC signature that this signer will generate.
func (s *eccSigner) EstimateSize() uint {
	return s.keyLen
}

// (AI GENERATED DESCRIPTION): Computes a SHA‑256 digest of the provided buffers and returns the ASN.1‑encoded ECDSA signature using the signer's private key.
func (s *eccSigner) Sign(covered enc.Wire) ([]byte, error) {
	h := sha256.New()
	for _, buf := range covered {
		_, err := h.Write(buf)
		if err != nil {
			return nil, enc.ErrUnexpected{Err: err}
		}
	}
	digest := h.Sum(nil)
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// (AI GENERATED DESCRIPTION): Returns the ECC signer's public key encoded as an X.509 PKIX byte slice.
func (s *eccSigner) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&s.key.PublicKey)
}

// (AI GENERATED DESCRIPTION): Returns the EC private key associated with the signer, encoded as a DER‑encoded byte slice (or an error if marshalling fails).
func (s *eccSigner) Secret() ([]byte, error) {
	return x509.MarshalECPrivateKey(s.key)
}

// NewEccSigner creates a signer using ECDSA key
func NewEccSigner(name enc.Name, key *ecdsa.PrivateKey) ndn.Signer {
	keyLen := (key.Curve.Params().BitSize*2 + 7) / 8
	keyLen += keyLen%2 + 8
	return &eccSigner{
		name:   name,
		key:    key,
		keyLen: uint(keyLen),
	}
}

// KeygenEcc creates a signer using a new ECDSA key
func KeygenEcc(name enc.Name, curve elliptic.Curve) (ndn.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, enc.ErrUnexpected{Err: err}
	}
	return NewEccSigner(name, key), nil
}

// ParseEcc parses a signer from a byte slice.
func ParseEcc(name enc.Name, key []byte) (ndn.Signer, error) {
	sk, err := x509.ParseECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return NewEccSigner(name, sk), nil
}

// validateEcdsa verifies the signature with a known ECC public key.
// ndn-cxx's PIB uses secp256r1 key stored in ASN.1 DER format. Use x509.ParsePKIXPublicKey to parse.
func validateEcdsa(sigCovered enc.Wire, sig ndn.Signature, pubKey *ecdsa.PublicKey) bool {
	if sig.SigType() != ndn.SignatureSha256WithEcdsa {
		return false
	}
	h := sha256.New()
	for _, buf := range sigCovered {
		_, err := h.Write(buf)
		if err != nil {
			return false
		}
	}
	digest := h.Sum(nil)
	return ecdsa.VerifyASN1(pubKey, digest, sig.SigValue())
}
