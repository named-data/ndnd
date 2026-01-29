package signer_test

import (
	"encoding/base64"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

const RSA_KEY_SECRET = `
MIICXQIBAAKBgQDnAl2p6DgmWm6brxxbm/Ujec4TDc1Y8pDQocSUmbx9irFOh9nf
wiZqO9YANcH/Lmy+3Ohf/O42BttdNPVBUzr3TcvUWy9Cb9LmS/aZnaom20phzXzx
id5BcCmbWrbqITEjaHWcE+Tbh8Cel/yUo5jA/JZn87Xb1jXzrPkzjK4kWQIDAQAB
AoGBAIAHvaWHQGdxQ1AhkxPqschBn8bLpX2gokYfAfZh5iemEHK3tDbhQa0rEIX5
RVWKg1ac1GUup09mKXnU+gCEgm60GPY+Kdsdz6fbFbe/Ipkv8SQd7SDfJuLTwMTL
V9YNMx0A9h92gQh3Ra0uvYoCxrGqks5THOV+mq4eySDxj9IBAkEA+US67BoSP5Us
7d7VNDxucNCDhjaU1FqYFV3yseEM055KaR2WeEzzLCSyfVSFaPwaMF8yHPWXfF+I
hPZuacYMeQJBAO0/Z2uAbDKz1ob5gtSgl1B6/tx1qcVKIqW/YJIxS9oMK/Pjy9Ze
7JlAIADQK/ucfk3+2Pz4nnwz5im4xGmfHuECQQCu6RaNBAJYEXJUe+95VwpcKUSR
Ug1/MQ7Ut3bMcNHSUJmARx3FzqE4EYwZu8xdjcFGvhXpEkA5KsQeINn7aNhpAkAT
9RZ1E5uGdFxihFC+JDg2W/Jeh0Ndxku916h/A8iWshlsbcgy409R4PQQPXLFurdh
RkPom91xI0iET/etzuXhAkBencrXnDjvLdRZZwlrODLvD41nj0eGbcZ5eGJGYA36
XsCWJ2KesIeRPNKy7NszvOCMYAmKQqc5Eapo6cKrCPiK
`

const RSA_KEY_DATA = `
Bv0BzAcbCANuZG4IBWFsaWNlCANLRVkICGWa8hUh/zLxFAMYAQkV/QFAMIIBPAIB
AAJBAMK+3/rBUKWWpcEvzYbCpH++AZRNdc/bi68yk7Jz3rh59r8nmXRzpSqMZk7h
CsFdf2ZbLr8SG7DiVBfybWUUWS8CAwEAAQJBALjwhUnfnZOzLbP5joekfo1lRqCs
su3zA4McV9DHYsHyP+Fc8RNsPHdGTej7UsYLTgs8YnR3bpqMHZIBPzBydBECIQDP
n3pSKuGz1382C1e7XSobK0sMrXitwNH3IgL8A9u+uQIhAPAfRkVsLI/6DHa9dT8U
pAvlKsnhSO12dpx8cxJ0PyMnAiEAs3Mfgk1V7t7fMJL1LRgFAJ6Wq0pz95mk4Hkh
IzkigOECIEwrT4o0D0q4of2Eic2xyXvwfQs/CHgzLNrk60e+UkzfAiEAzpD+LoX8
Llj+jzlKvw7OHWgkoEsuJTYAFBXbmfUipNsWIhsBARwdBxsIA25kbggFYWxpY2UI
A0tFWQgIZZryFSH/MvEXQDoSdUxZGOb0CUEMyTRMSwATWWkUsG9uyrvnVxLk2Mb7
qEa4Xg1H5/+zKy2mdI82/AcbsQJslRxC32g0ZfmDPKs=
`

var RSA_KEY_NAME, _ = enc.NameFromStr("/ndn/alice/KEY/e%9A%F2%15%21%FF2%F1")

// (AI GENERATED DESCRIPTION): Serializes a signer’s secret into a Data packet and verifies that the resulting packet has the expected ContentType, Name, and Content.
func TestMarshalSecret(t *testing.T) {
	tu.SetT(t)

	// create signer
	secret, _ := base64.StdEncoding.DecodeString(RSA_KEY_SECRET)
	signer := tu.NoErr(sig.ParseRsa(RSA_KEY_NAME, secret))

	// encode signer secret
	wire := tu.NoErr(sig.MarshalSecret(signer))

	// check output data
	data, _, err := spec.Spec{}.ReadData(enc.NewWireView(wire))
	require.NoError(t, err)
	require.Equal(t, ndn.ContentTypeSigningKey, data.ContentType().Unwrap())
	require.Equal(t, RSA_KEY_NAME, data.Name())
	require.Equal(t, secret, data.Content().Join())
}

// (AI GENERATED DESCRIPTION): Tests that `sig.UnmarshalSecret` correctly parses a raw RSA secret key and returns a signer with the expected signature type and key name.
func TestUnmarshalSecret(t *testing.T) {
	tu.SetT(t)

	// get static secret data
	dataRaw := tu.NoErr(base64.StdEncoding.DecodeString(RSA_KEY_DATA))
	data, _, err := spec.Spec{}.ReadData(enc.NewBufferView(dataRaw))
	require.NoError(t, err)

	signer, err := sig.UnmarshalSecret(data)
	require.NoError(t, err)

	// check output signer
	require.Equal(t, ndn.SignatureSha256WithRsa, signer.Type())
	require.Equal(t, RSA_KEY_NAME, signer.KeyName())
}

// Ensure marshal works when the signer is wrapped in a ContextSigner (e.g., to override the key locator).
func TestMarshalSecretContextSigner(t *testing.T) {
	tu.SetT(t)

	secret, _ := base64.StdEncoding.DecodeString(RSA_KEY_SECRET)
	baseSigner := tu.NoErr(sig.ParseRsa(RSA_KEY_NAME, secret))
	keyLocator := RSA_KEY_NAME.Append(enc.NewGenericComponent("loc"))
	ctxSigner := sig.WithKeyLocator(baseSigner, keyLocator)

	wire := tu.NoErr(sig.MarshalSecret(ctxSigner))

	data, _, err := spec.Spec{}.ReadData(enc.NewWireView(wire))
	require.NoError(t, err)
	require.Equal(t, ndn.ContentTypeSigningKey, data.ContentType().Unwrap())
	require.Equal(t, RSA_KEY_NAME, data.Name())
	require.Equal(t, secret, data.Content().Join())
	require.Equal(t, keyLocator, data.Signature().KeyName())
}
