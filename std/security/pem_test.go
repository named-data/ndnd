package security_test

import (
	"encoding/base64"
	"testing"

	"github.com/named-data/ndnd/std/security"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): TestPemEncodeCert verifies that the security.PemEncode function correctly converts a DER‑encoded certificate into its PEM representation.
func TestPemEncodeCert(t *testing.T) {
	tu.SetT(t)

	cert, _ := base64.StdEncoding.DecodeString(CERT_ROOT)
	res := tu.NoErr(security.PemEncode(cert))
	require.Equal(t, CERT_ROOT_PEM, string(res))
}

// (AI GENERATED DESCRIPTION): Tests that the `security.PemDecode` function correctly converts a PEM‑encoded certificate string into its original DER‑encoded byte form.
func TestPemDecodeCert(t *testing.T) {
	tu.SetT(t)

	cert, _ := base64.StdEncoding.DecodeString(CERT_ROOT)
	res := security.PemDecode([]byte(CERT_ROOT_PEM))
	require.Equal(t, cert, res[0])
}
