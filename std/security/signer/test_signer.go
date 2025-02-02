package signer

import (
	"crypto/rand"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// testSigner is a signer used for test only.
// It gives a signature value with a random size.
type testSigner struct {
	keyName enc.Name
	sigSize int
}

func (testSigner) Type() ndn.SigType {
	return ndn.SignatureEmptyTest
}

func (t testSigner) KeyName() enc.Name {
	return t.keyName
}

func (t testSigner) KeyLocator() enc.Name {
	return t.keyName
}

func (t testSigner) EstimateSize() uint {
	return uint(t.sigSize)
}

func (t testSigner) Sign(covered enc.Wire) ([]byte, error) {
	buf := make([]byte, t.sigSize)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (testSigner) Public() ([]byte, error) {
	return nil, ndn.ErrNoPubKey
}

// NewTestSigner creates an empty signer for test.
func NewTestSigner(keyName enc.Name, sigSize int) ndn.Signer {
	return testSigner{}
}
