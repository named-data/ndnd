package security

import (
	"crypto/ed25519"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/utils"
)

// edSigner is a signer that uses Ed25519 key to sign packets.
type edSigner struct {
	timer ndn.Timer
	seq   uint64

	keyLocatorName enc.Name
	key            ed25519.PrivateKey
	forCert        bool
	forInt         bool
	certExpireTime time.Duration
}

func (s *edSigner) SigInfo() (*ndn.SigConfig, error) {
	ret := &ndn.SigConfig{
		Type:    ndn.SignatureEd25519,
		KeyName: s.keyLocatorName,
	}
	if s.forCert {
		ret.NotBefore = utils.IdPtr(s.timer.Now())
		ret.NotAfter = utils.IdPtr(s.timer.Now().Add(s.certExpireTime))
	}
	if s.forInt {
		s.seq++
		ret.Nonce = s.timer.Nonce()
		ret.SigTime = utils.IdPtr(s.timer.Now())
		ret.SeqNum = utils.IdPtr(s.seq)
	}
	return ret, nil
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
		timer:          basic_engine.Timer{},
		seq:            0,
		keyLocatorName: keyLocatorName,
		key:            key,
		forCert:        forCert,
		forInt:         forInt,
		certExpireTime: expireTime,
	}
}
