package signer

import (
	"bytes"
	"crypto/sha256"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// sha256Signer is a Data signer that uses DigestSha256.
type sha256Signer struct{}

// (AI GENERATED DESCRIPTION): Returns the NDN signature type used by this signer, namely `SignatureDigestSha256`.
func (sha256Signer) Type() ndn.SigType {
	return ndn.SignatureDigestSha256
}

// (AI GENERATED DESCRIPTION): Returns nil, indicating that the sha256Signer does not associate a key name.
func (sha256Signer) KeyName() enc.Name {
	return nil
}

// (AI GENERATED DESCRIPTION): Returns the key locator for this signer; the `sha256Signer` does not provide a key locator, so it simply returns `nil`.
func (sha256Signer) KeyLocator() enc.Name {
	return nil
}

// (AI GENERATED DESCRIPTION): Returns the estimated size of a SHA‑256 signature, which is 32 bytes.
func (sha256Signer) EstimateSize() uint {
	return 32
}

// (AI GENERATED DESCRIPTION): Computes a SHA‑256 hash over the supplied covered buffers and returns it as the signature.
func (sha256Signer) Sign(covered enc.Wire) ([]byte, error) {
	h := sha256.New()
	for _, buf := range covered {
		_, err := h.Write(buf)
		if err != nil {
			return nil, enc.ErrUnexpected{Err: err}
		}
	}
	return h.Sum(nil), nil
}

// (AI GENERATED DESCRIPTION): Returns nil and ErrNoPubKey, indicating that the SHA‑256 signer does not expose a public key.
func (sha256Signer) Public() ([]byte, error) {
	return nil, ndn.ErrNoPubKey
}

// NewSha256Signer creates a signer that uses DigestSha256.
func NewSha256Signer() ndn.Signer {
	return sha256Signer{}
}

// ValidateSha256 checks if the signature is valid for the covered data.
func ValidateSha256(sigCovered enc.Wire, sig ndn.Signature) bool {
	if sig.SigType() != ndn.SignatureDigestSha256 {
		return false
	}
	h := sha256.New()
	for _, buf := range sigCovered {
		_, err := h.Write(buf)
		if err != nil {
			return false
		}
	}
	return bytes.Equal(h.Sum(nil), sig.SigValue())
}
