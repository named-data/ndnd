package security

import (
	"crypto/ed25519"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
)

// edSigner is a signer that uses Ed25519 key to sign packets.
type edSigner struct {
	asymSigner
	key ed25519.PrivateKey
}

func (s *edSigner) SigInfo() (*ndn.SigConfig, error) {
	return s.genSigInfo(ndn.SignatureEd25519)
}

func (s *edSigner) EstimateSize() uint {
	return ed25519.SignatureSize
}

func (s *edSigner) ComputeSigValue(covered enc.Wire) ([]byte, error) {
	return ed25519.Sign(s.key, covered.Join()), nil
}

// NewEdSigner creates a signer using ed25519 key
func NewEdSigner(
	forCert bool, forInt bool, expireTime time.Duration, key ed25519.PrivateKey,
	keyLocatorName enc.Name,
) ndn.Signer {
	return &edSigner{
		asymSigner: asymSigner{
			timer:          basic_engine.Timer{},
			seq:            0,
			keyLocatorName: keyLocatorName,
			forCert:        forCert,
			forInt:         forInt,
			certExpireTime: expireTime,
		},
		key: key,
	}
}

// Ed25519DerivePubKey derives the public key from a private key.
func Ed25519DerivePubKey(privKey ed25519.PrivateKey) ed25519.PublicKey {
	return ed25519.PublicKey(privKey[ed25519.PublicKeySize:])
}
