package security

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/utils"
)

// asymSigner is a base class of signer used for asymmetric keys.
type asymSigner struct {
	timer ndn.Timer
	seq   uint64

	keyLocatorName enc.Name
	forCert        bool
	forInt         bool
	certExpireTime time.Duration
}

func (s *asymSigner) genSigInfo(sigType ndn.SigType) (*ndn.SigConfig, error) {
	ret := &ndn.SigConfig{
		Type:    sigType,
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
