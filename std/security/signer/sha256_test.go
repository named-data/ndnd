package signer_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	sig "github.com/named-data/ndnd/std/security/signer"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests that the Sha256Signer produces the correct signature type, size, key name, and digest when signing the byte slice "hello".
func TestSha256Signer(t *testing.T) {
	tu.SetT(t)

	// Create a signature.
	signer := sig.NewSha256Signer()
	sig := tu.NoErr(signer.Sign(enc.Wire{[]byte("hello")}))

	require.Equal(t, ndn.SignatureDigestSha256, signer.Type())
	require.Equal(t, uint(32), signer.EstimateSize())
	require.Equal(t, enc.Name(nil), signer.KeyName())
	require.Equal(t, []byte{
		0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5,
		0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04,
		0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
	}, sig)
}
