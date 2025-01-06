package security

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
)

// rsaSigner is a signer that uses ECC key to sign packets.
type rsaSigner struct {
	asymSigner
	keyLen uint
	key    *rsa.PrivateKey
}

func (s *rsaSigner) SigInfo() (*ndn.SigConfig, error) {
	return s.genSigInfo(ndn.SignatureSha256WithRsa)
}

func (s *rsaSigner) EstimateSize() uint {
	return s.keyLen
}

func (s *rsaSigner) ComputeSigValue(covered enc.Wire) ([]byte, error) {
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

// NewRsaSigner creates a signer using RSA key
func NewRsaSigner(
	forCert bool, forInt bool, expireTime time.Duration, key *rsa.PrivateKey,
	keyLocatorName enc.Name,
) ndn.Signer {
	keyLen := uint(key.Size())
	return &rsaSigner{
		asymSigner: asymSigner{
			timer:          basic_engine.Timer{},
			seq:            0,
			keyLocatorName: keyLocatorName,

			forCert:        forCert,
			forInt:         forInt,
			certExpireTime: expireTime,
		},
		key:    key,
		keyLen: keyLen,
	}
}
