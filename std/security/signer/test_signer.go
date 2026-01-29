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

// (AI GENERATED DESCRIPTION): Returns the signature type for this test signer, which is the empty test signature (`ndn.SignatureEmptyTest`).
func (testSigner) Type() ndn.SigType {
	return ndn.SignatureEmptyTest
}

// (AI GENERATED DESCRIPTION): Returns the name of the key used by the test signer.
func (t testSigner) KeyName() enc.Name {
	return t.keyName
}

// (AI GENERATED DESCRIPTION): Returns the key locator name (`keyName`) associated with this test signer.
func (t testSigner) KeyLocator() enc.Name {
	return t.keyName
}

// (AI GENERATED DESCRIPTION): Returns the estimated signature size (in bytes) for the testSigner.
func (t testSigner) EstimateSize() uint {
	return uint(t.sigSize)
}

// (AI GENERATED DESCRIPTION): Generates a pseudo‑random signature of length `t.sigSize` for the supplied data, returning it as a byte slice.
func (t testSigner) Sign(covered enc.Wire) ([]byte, error) {
	buf := make([]byte, t.sigSize)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// (AI GENERATED DESCRIPTION): Returns `nil` and `ndn.ErrNoPubKey`, indicating that this test signer does not provide a public key.
func (testSigner) Public() ([]byte, error) {
	return nil, ndn.ErrNoPubKey
}

// NewTestSigner creates an empty signer for test.
func NewTestSigner(keyName enc.Name, sigSize int) ndn.Signer {
	return testSigner{}
}
