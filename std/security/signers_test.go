package security_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
	"github.com/stretchr/testify/require"
)

func TestEddsaSignerBasic(t *testing.T) {
	utils.SetTestingT(t)

	keyLocatorName := utils.WithoutErr(enc.NameFromStr("/test/KEY/1"))
	edkeybits := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	signer := security.NewEdSigner(
		false, false, 0, edkeybits, keyLocatorName,
	)

	require.Equal(t, uint(ed25519.SignatureSize), signer.EstimateSize())
	signInfo := utils.WithoutErr(signer.SigInfo())
	require.Equal(t, 0, signInfo.KeyName.Compare(keyLocatorName))
	require.Equal(t, ndn.SignatureEd25519, signInfo.Type)

	dataVal := enc.Wire{[]byte(
		"\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix" +
			"\x14\x03\x18\x01\x00")}
	sigValue := utils.WithoutErr(signer.ComputeSigValue(dataVal))

	// For basic test, we use ed25519.Verify to verify the signature.
	require.True(t, ed25519.Verify(ed25519.PublicKey(edkeybits[ed25519.PublicKeySize:]), dataVal.Join(), sigValue))
}

func TestEddsaSignerCertificate(t *testing.T) {
	utils.SetTestingT(t)

	spec := spec_2022.Spec{}

	keyLocatorName := utils.WithoutErr(enc.NameFromStr("/test/KEY/1"))
	certName := utils.WithoutErr(enc.NameFromStr("/test/KEY/1/self/1"))
	edkeybits := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	signer := security.NewEdSigner(
		false, false, 3600*time.Second, edkeybits, keyLocatorName,
	)
	pubKeyBits := []byte(edkeybits[ed25519.PublicKeySize:])

	cert := utils.WithoutErr(spec.MakeData(certName, &ndn.DataConfig{
		ContentType: utils.IdPtr(ndn.ContentTypeKey),
		Freshness:   utils.IdPtr(3600 * time.Second),
	}, enc.Wire{pubKeyBits}, signer))

	data, covered, err := spec.ReadData(enc.NewWireReader(cert.Wire))
	require.NoError(t, err)

	require.True(t, security.EddsaValidate(covered, data.Signature(), pubKeyBits))
}
