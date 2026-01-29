package signer_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	sig "github.com/named-data/ndnd/std/security/signer"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

var TEST_KEY_NAME, _ = enc.NameFromStr("/KEY")

// (AI GENERATED DESCRIPTION): Verifies that the supplied Ed25519 signer signs a sample data packet correctly and that the resulting signature validates against the provided public key.
func testEd25519Verify(t *testing.T, signer ndn.Signer, verifyKey []byte) bool {
	require.Equal(t, uint(ed25519.SignatureSize), signer.EstimateSize())
	require.Equal(t, ndn.SignatureEd25519, signer.Type())
	require.Equal(t, TEST_KEY_NAME, signer.KeyName())

	dataVal := enc.Wire{
		[]byte("\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"),
		[]byte("\x14\x03\x18\x01\x00"),
	}
	sigValue := tu.NoErr(signer.Sign(dataVal))

	// For basic test, we use ed25519.Verify to verify the signature.
	verifyKeyBits := tu.NoErr(x509.ParsePKIXPublicKey(verifyKey)).(ed25519.PublicKey)
	return ed25519.Verify(verifyKeyBits, dataVal.Join(), sigValue)
}

// (AI GENERATED DESCRIPTION): Creates an Ed25519 signer from a seed, extracts its public key, and verifies that signatures produced by the signer are correctly validated.
func TestEd25519SignerNew(t *testing.T) {
	tu.SetT(t)

	edkeybits := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	signer := sig.NewEd25519Signer(TEST_KEY_NAME, edkeybits)
	pub := tu.NoErr(signer.Public())
	require.True(t, testEd25519Verify(t, signer, pub))
}

// (AI GENERATED DESCRIPTION): Tests that Ed25519 key generation produces unique key pairs and that each key’s public key correctly verifies signatures from its own signer.
func TestEd25519Keygen(t *testing.T) {
	tu.SetT(t)

	signer1 := tu.NoErr(sig.KeygenEd25519(TEST_KEY_NAME))
	pub1 := tu.NoErr(signer1.Public())
	require.True(t, testEd25519Verify(t, signer1, pub1))

	signer2 := tu.NoErr(sig.KeygenEd25519(TEST_KEY_NAME))
	pub2 := tu.NoErr(signer2.Public())
	require.True(t, testEd25519Verify(t, signer2, pub2))

	// Check that the two signers are different.
	require.False(t, testEd25519Verify(t, signer2, pub1))
}

// (AI GENERATED DESCRIPTION): Verifies that an Ed25519 signer can be reconstructed from its secret key and that attempting to parse a public key fails.
func TestEd25519Parse(t *testing.T) {
	tu.SetT(t)

	edkeybits := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	signer1 := sig.NewEd25519Signer(TEST_KEY_NAME, edkeybits)

	secret := tu.NoErr(sig.GetSecret(signer1))
	signer2 := tu.NoErr(sig.ParseEd25519(TEST_KEY_NAME, secret))

	// Check that the two signers are the same.
	pub1 := tu.NoErr(signer1.Public())
	require.True(t, testEd25519Verify(t, signer2, pub1))

	// Make sure parse fails with the public key.
	pub2 := tu.NoErr(signer1.Public())
	_, err := sig.ParseEd25519(TEST_KEY_NAME, pub2)
	require.Error(t, err)
}
