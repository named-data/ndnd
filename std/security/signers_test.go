package security_test

import (
	"crypto/ed25519"
	"encoding/base64"
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
	require.True(t, ed25519.Verify(security.Ed25519DerivePubKey(edkeybits), dataVal.Join(), sigValue))
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
	pubKey := security.Ed25519DerivePubKey(edkeybits)
	pubKeyBits := security.Ed25519PubKeyToDER(pubKey)

	cert := utils.WithoutErr(spec.MakeData(certName, &ndn.DataConfig{
		ContentType: utils.IdPtr(ndn.ContentTypeKey),
		Freshness:   utils.IdPtr(3600 * time.Second),
	}, enc.Wire{pubKeyBits}, signer))

	data, covered, err := spec.ReadData(enc.NewWireReader(cert.Wire))
	require.NoError(t, err)

	pubKeyParsedBits := data.Content().Join()
	pubKeyParsed := utils.WithoutErr(security.Ed25519PubKeyFromDER(pubKeyParsedBits))

	require.True(t, security.EddsaValidate(covered, data.Signature(), pubKeyParsed))
}

// TestEddsaSignerCertificate2 tests the validator using a given certificate for interoperability.
func TestEddsaSignerCertificate2(t *testing.T) {
	utils.SetTestingT(t)

	const TestCert = `
Bv0BCgc1CAxFZDI1NTE5LWRlbW8IA0tFWQgQNWE2MTVkYjdjZjA2MDNiNQgEc2Vs
ZjYIAAABgQD8AY0UCRgBAhkEADbugBUsMCowBQYDK2VwAyEAQxUZBL+3I3D4oDIJ
tJvuCTguHM7AUbhlhA/wu8ZhrkwWVhsBBRwnByUIDEVkMjU1MTktZGVtbwgDS0VZ
CBA1YTYxNWRiN2NmMDYwM2I1/QD9Jv0A/g8xOTcwMDEwMVQwMDAwMDD9AP8PMjAy
MjA1MjZUMTUyODQ0F0DAAWCZzxQSCAV0tluFDry5aT1b+EgoYgT1JKxbKVb/tINx
M43PFy/2hDe8j61PuYD9tCah0TWapPwfXWi3fygA`
	spec := spec_2022.Spec{}

	certWire := utils.WithoutErr(base64.RawStdEncoding.DecodeString(TestCert))
	certData, covered, err := spec.ReadData(enc.NewBufferReader(certWire))
	require.NoError(t, err)

	pubKeyBits := utils.WithoutErr(security.Ed25519PubKeyFromDER(certData.Content().Join()))
	require.True(t, security.EddsaValidate(covered, certData.Signature(), pubKeyBits))
}
