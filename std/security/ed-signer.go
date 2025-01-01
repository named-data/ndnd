package security

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/utils"
)

const ASN1Ed25519PrivKeyPrefix = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"
const ASN1Ed25519PubKeyPrefix = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"

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

// Ed25519DerivePubKey derives the public key from a private key.
func Ed25519DerivePubKey(privKey ed25519.PrivateKey) ed25519.PublicKey {
	return ed25519.PublicKey(privKey[ed25519.PublicKeySize:])
}

// Ed25519PrivKeyToDER converts a raw ed25519 private key to 48B DER format.
// This works by prepending the fixed ASN.1 header.
func Ed25519PrivKeyToDER(privKey ed25519.PrivateKey) []byte {
	seed := privKey.Seed()
	return append([]byte(ASN1Ed25519PrivKeyPrefix), seed...)
}

// Ed25519PrivKeyFromDER converts a 48B DER ed25519 private key to go ed25519.PrivateKey.
func Ed25519PrivKeyFromDER(privKeyBits []byte) (ed25519.PrivateKey, error) {
	if len(privKeyBits) != ed25519.SeedSize+len(ASN1Ed25519PrivKeyPrefix) {
		return nil, errors.New("invalid ed25519 private key in DER form")
	}
	if !bytes.HasPrefix(privKeyBits, []byte(ASN1Ed25519PrivKeyPrefix)) {
		return nil, errors.New("invalid ed25519 private key in DER form")
	}
	return ed25519.NewKeyFromSeed(privKeyBits[len(ASN1Ed25519PrivKeyPrefix):]), nil
}

// Ed25519PubKeyToDER converts a 32B raw ed25519 public key to 44B DER format.
// This works by prepending the fixed ASN.1 header.
func Ed25519PubKeyToDER(pubKey ed25519.PublicKey) []byte {
	return append([]byte(ASN1Ed25519PubKeyPrefix), pubKey...)
}

// Ed25519PubKeyFromDER converts a 44B DER ed25519 private key to go ed25519.PrivateKey.
func Ed25519PubKeyFromDER(pubKeyBits []byte) (ed25519.PublicKey, error) {
	if len(pubKeyBits) != ed25519.PublicKeySize+len(ASN1Ed25519PubKeyPrefix) {
		return nil, errors.New("invalid ed25519 public key in DER form")
	}
	if !bytes.HasPrefix(pubKeyBits, []byte(ASN1Ed25519PubKeyPrefix)) {
		return nil, errors.New("invalid ed25519 public key in DER form")
	}
	return pubKeyBits[len(ASN1Ed25519PubKeyPrefix):], nil
}
