package security_test

import (
	"encoding/base64"
	"testing"

	"github.com/named-data/ndnd/std/security"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Unit tests for `security.DecodeFile`, verifying that it correctly parses TLV and PEM‑encoded certificates and keys while handling malformed or empty input gracefully.
func TestDecodeFile(t *testing.T) {
	tu.SetT(t)

	// Decode TLV certificate
	certRootTlv, _ := base64.StdEncoding.DecodeString(CERT_ROOT)
	signers, certs, err := security.DecodeFile(certRootTlv)
	require.NoError(t, err)
	require.Len(t, signers, 0)
	require.Len(t, certs, 1)

	// Decode TLV key
	aliceKeyTlv, _ := base64.StdEncoding.DecodeString(KEY_ALICE)
	signers, certs, err = security.DecodeFile(aliceKeyTlv)
	require.NoError(t, err)
	require.Len(t, signers, 1)
	require.Len(t, certs, 0)
	require.Equal(t, KEY_ALICE_NAME, signers[0].KeyName())

	// Decode PEM certificate
	signers, certs, err = security.DecodeFile([]byte(CERT_ROOT_PEM))
	require.NoError(t, err)
	require.Len(t, signers, 0)
	require.Len(t, certs, 1)

	// Decode PEM key
	signers, certs, err = security.DecodeFile([]byte(KEY_ALICE_PEM))
	require.NoError(t, err)
	require.Len(t, signers, 1)
	require.Len(t, certs, 0)

	// Decode multiple PEM entries
	concat := []byte(CERT_ROOT_PEM + "\n" + KEY_ALICE_PEM)
	signers, certs, err = security.DecodeFile(concat)
	require.NoError(t, err)
	require.Len(t, signers, 1)
	require.Len(t, certs, 1)
	require.Equal(t, KEY_ALICE_NAME, signers[0].KeyName())

	// Decode partially valid content
	concat = []byte(CERT_ROOT_PEM + "\n" + "invalid")
	signers, certs, err = security.DecodeFile(concat)
	require.NoError(t, err)
	require.Len(t, signers, 0)
	require.Len(t, certs, 1)

	// Decode invalid text content
	_, _, err = security.DecodeFile([]byte("invalid"))
	require.Error(t, err)

	// Decode invalid binary content (0x01)
	_, _, err = security.DecodeFile([]byte{0x01, 0x33, 0x03})
	require.Error(t, err)

	// Decode invalid TLV data (0x06)
	signers, certs, err = security.DecodeFile([]byte{0x06, 0x33, 0x03})
	require.NoError(t, err)
	require.Len(t, signers, 0)
	require.Len(t, certs, 0)

	// Decode invalid Data packet
	signers, certs, err = security.DecodeFile([]byte{0x06, 0x03, 0x00, 0x00, 0x00})
	require.NoError(t, err)
	require.Len(t, signers, 0)
	require.Len(t, certs, 0)

	// Decode empty content
	_, _, err = security.DecodeFile([]byte{})
	require.Error(t, err)
}
