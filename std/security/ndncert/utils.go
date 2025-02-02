package ndncert

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
)

// IsError checks if a packet contains an NDNCERT error.
func IsError(wire enc.Wire) error {
	msg, _ := tlv.ParseErrorRes(enc.NewFastReader(wire), true)
	if msg == nil || msg.ErrCode == 0 {
		return nil
	}
	return fmt.Errorf("ndncert error: %s (%d)", msg.ErrInfo, msg.ErrCode)
}

// EcdhKeygen generates an ECDH key pair.
func EcdhKeygen() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// EcdhHkdf computes a shared secret using ECDH and HKDF.
func EcdhHkdf(skey *ecdh.PrivateKey, pkey []byte, salt []byte, info []byte) ([]byte, error) {
	caEcdhKey, err := ecdh.P256().NewPublicKey(pkey)
	if err != nil {
		return nil, err
	}

	secret, err := skey.ECDH(caEcdhKey)
	if err != nil {
		return nil, err
	}

	hkdf := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}

	return key, nil
}
