package security

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
)

// eccSigner is a signer that uses ECC key to sign packets.
type eccSigner struct {
	asymSigner
	keyLen uint
	key    *ecdsa.PrivateKey
}

func (s *eccSigner) SigInfo() (*ndn.SigConfig, error) {
	return s.genSigInfo(ndn.SignatureSha256WithEcdsa)
}

func (s *eccSigner) EstimateSize() uint {
	return s.keyLen
}

func (s *eccSigner) ComputeSigValue(covered enc.Wire) ([]byte, error) {
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

// NewEccSigner creates a signer using ECDSA key
func NewEccSigner(
	forCert bool, forInt bool, expireTime time.Duration, key *ecdsa.PrivateKey,
	keyLocatorName enc.Name,
) ndn.Signer {
	keyLen := uint(key.Curve.Params().BitSize*2+7) / 8
	keyLen += keyLen%2 + 8
	return &eccSigner{
		asymSigner: asymSigner{
			timer:          basic_engine.Timer{},
			seq:            0,
			keyLocatorName: keyLocatorName,
			forCert:        forCert,
			forInt:         forInt,
			certExpireTime: expireTime,
		},
		keyLen: keyLen,
		key:    key,
	}
}
