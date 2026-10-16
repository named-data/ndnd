package security_test

import (
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/stretchr/testify/require"
)

// ValidateAtSignatureTime must handle a nil Data (the certificate itself is
// being validated, so the sig-time check is deferred) without panicking.
func TestValidateAtSignatureTimeNilData(t *testing.T) {
	rootName, err := enc.NameFromStr("/test/root")
	require.NoError(t, err)
	rootSigner, err := signer.KeygenEd25519(sec.MakeKeyName(rootName))
	require.NoError(t, err)
	secretWire, err := signer.MarshalSecret(rootSigner)
	require.NoError(t, err)
	opts := SignCertOptions{
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(-1 * time.Hour), // expired
	}
	_, certData, _ := signCert(rootSigner, secretWire, opts)

	completed := false
	require.NotPanics(t, func() {
		sec.ValidateAtSignatureTime(ndn.CertExpiredCallbackArgs{
			Data: nil, // certificate itself is being validated
			Cert: certData,
		}, func(err error) {
			completed = true
			require.NoError(t, err)
		})
	})
	require.True(t, completed)
}

// ValidateSigTime must reject a nil Data instead of panicking.
func TestValidateSigTimeNilData(t *testing.T) {
	rootName, err := enc.NameFromStr("/test/root")
	require.NoError(t, err)
	rootSigner, err := signer.KeygenEd25519(sec.MakeKeyName(rootName))
	require.NoError(t, err)
	secretWire, err := signer.MarshalSecret(rootSigner)
	require.NoError(t, err)
	opts := SignCertOptions{
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(-1 * time.Hour),
	}
	_, certData, _ := signCert(rootSigner, secretWire, opts)

	require.NotPanics(t, func() {
		require.False(t, sec.ValidateSigTime(nil, certData))
	})
}
