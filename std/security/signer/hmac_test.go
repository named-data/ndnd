package signer_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	sig "github.com/named-data/ndnd/std/security/signer"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests HMAC signing by creating an HmacSigner with a key, signing a sample payload, and asserting the signature type, estimated size, key name, and expected signature bytes.
func TestHmacSigner(t *testing.T) {
	tu.SetT(t)

	// Create a signature.
	signer := sig.NewHmacSigner([]byte("mykey"))
	signature := tu.NoErr(signer.Sign(enc.Wire{[]byte("hello")}))

	require.Equal(t, ndn.SignatureHmacWithSha256, signer.Type())
	require.Equal(t, uint(32), signer.EstimateSize())
	require.Equal(t, enc.Name(nil), signer.KeyName())
	require.Equal(t, []byte{
		0x1b, 0x1c, 0xae, 0x65, 0x39, 0x9e, 0xe1, 0x06, 0x4e, 0x57, 0x64,
		0x63, 0x93, 0xf7, 0xbb, 0x03, 0x5f, 0x4f, 0xe6, 0x0b, 0x54, 0x13,
		0x50, 0x9d, 0x73, 0xff, 0xce, 0x40, 0xcd, 0x79, 0xa5, 0x35,
	}, signature)
}
