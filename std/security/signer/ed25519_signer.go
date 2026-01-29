package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// ed25519Signer is a signer that uses Ed25519 key to sign packets.
type ed25519Signer struct {
	name enc.Name
	key  ed25519.PrivateKey
}

// (AI GENERATED DESCRIPTION): Returns the signature type constant (SignatureEd25519) indicating that this signer uses Ed25519.
func (s *ed25519Signer) Type() ndn.SigType {
	return ndn.SignatureEd25519
}

// (AI GENERATED DESCRIPTION): Returns the name of the ed25519 key associated with the signer.
func (s *ed25519Signer) KeyName() enc.Name {
	return s.name
}

// (AI GENERATED DESCRIPTION): Returns the name that identifies the signer’s key (the key‑locator name).
func (s *ed25519Signer) KeyLocator() enc.Name {
	return s.name
}

// (AI GENERATED DESCRIPTION): Estimates the fixed size (in bytes) of an Ed25519 signature.
func (s *ed25519Signer) EstimateSize() uint {
	return ed25519.SignatureSize
}

// (AI GENERATED DESCRIPTION): Signs the supplied data (by concatenating its wire fragments) with the signer’s Ed25519 private key and returns the resulting signature.
func (s *ed25519Signer) Sign(covered enc.Wire) ([]byte, error) {
	return ed25519.Sign(s.key, covered.Join()), nil
}

// (AI GENERATED DESCRIPTION): Returns the ed25519 signer’s public key encoded in DER‑format PKIX bytes.
func (s *ed25519Signer) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(s.key.Public())
}

// (AI GENERATED DESCRIPTION): Returns the ed25519 private key encoded as a PKCS#8 DER byte slice.
func (s *ed25519Signer) Secret() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(s.key)
}

// NewEd25519Signer creates a signer using ed25519 key
func NewEd25519Signer(name enc.Name, key ed25519.PrivateKey) ndn.Signer {
	return &ed25519Signer{name, key}
}

// Ed25519Keygen creates a signer using a new Ed25519 key
func KeygenEd25519(name enc.Name) (ndn.Signer, error) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewEd25519Signer(name, sk), nil
}

// ParseEd25519 parses a signer from a byte slice.
func ParseEd25519(name enc.Name, key []byte) (ndn.Signer, error) {
	pkey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	sk, ok := pkey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}
	return NewEd25519Signer(name, sk), nil
}

// validateEd25519 verifies the signature with a known ed25519 public key.
// ndn-cxx's PIB does not support this, but a certificate is supposed to use ASN.1 DER format.
// Use x509.ParsePKIXPublicKey to parse. Note: ed25519.PublicKey is defined to be a pointer type without '*'.
func validateEd25519(sigCovered enc.Wire, sig ndn.Signature, pubKey ed25519.PublicKey) bool {
	if sig.SigType() != ndn.SignatureEd25519 {
		return false
	}
	return ed25519.Verify(pubKey, sigCovered.Join(), sig.SigValue())
}
