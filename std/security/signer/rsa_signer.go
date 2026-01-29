package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// rsaSigner is a signer that uses ECC key to sign packets.
type rsaSigner struct {
	name enc.Name
	key  *rsa.PrivateKey
}

// (AI GENERATED DESCRIPTION): Returns the signature type for the RSA signer, indicating that it uses SHA‑256 with RSA.
func (s *rsaSigner) Type() ndn.SigType {
	return ndn.SignatureSha256WithRsa
}

// (AI GENERATED DESCRIPTION): Returns the key name (`enc.Name`) used by this RSA signer.
func (s *rsaSigner) KeyName() enc.Name {
	return s.name
}

// (AI GENERATED DESCRIPTION): Returns the name of the key that serves as the KeyLocator for this RSA signer.
func (s *rsaSigner) KeyLocator() enc.Name {
	return s.name
}

// (AI GENERATED DESCRIPTION): Estimates the byte length of an RSA signature that this signer would produce, based on the RSA key size.
func (s *rsaSigner) EstimateSize() uint {
	return uint(s.key.Size())
}

// (AI GENERATED DESCRIPTION): Generates an RSA PKCS#1 v1.5 signature by hashing the concatenated buffers in the supplied covered wire with SHA‑256 and signing the resulting digest using the signer’s private key.
func (s *rsaSigner) Sign(covered enc.Wire) ([]byte, error) {
	h := sha256.New()
	for _, buf := range covered {
		_, err := h.Write(buf)
		if err != nil {
			return nil, enc.ErrUnexpected{Err: err}
		}
	}
	digest := h.Sum(nil)
	return rsa.SignPKCS1v15(nil, s.key, crypto.SHA256, digest)
}

// (AI GENERATED DESCRIPTION): Returns the RSA public key of the signer encoded as a PKIX ASN.1 DER byte slice.
func (s *rsaSigner) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&s.key.PublicKey)
}

// (AI GENERATED DESCRIPTION): Returns the RSA signer’s private key encoded as PKCS#1 DER‑formatted bytes.
func (s *rsaSigner) Secret() ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(s.key), nil
}

// NewRsaSigner creates a signer using RSA key
func NewRsaSigner(name enc.Name, key *rsa.PrivateKey) ndn.Signer {
	return &rsaSigner{name, key}
}

// KeygenRsa creates a signer using a new RSA key
func KeygenRsa(name enc.Name, size int) (ndn.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, enc.ErrUnexpected{Err: err}
	}
	return NewRsaSigner(name, key), nil
}

// ParseRsa creates a signer using a RSA key bytes
func ParseRsa(name enc.Name, key []byte) (ndn.Signer, error) {
	sk, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return NewRsaSigner(name, sk), nil
}

// ValidateRsa verifies the signature with a known RSA public key.
// ndn-cxx's PIB uses RSA 2048 key stored in ASN.1 DER format.
// Use x509.ParsePKIXPublicKey to parse.
func ValidateRsa(sigCovered enc.Wire, sig ndn.Signature, pubKey *rsa.PublicKey) bool {
	if sig.SigType() != ndn.SignatureSha256WithRsa {
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
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, sig.SigValue()) == nil
}
