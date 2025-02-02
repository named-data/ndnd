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
MIIBPAIBAAJBAMK+3/rBUKWWpcEvzYbCpH++AZRNdc/bi68yk7Jz3rh59r8nmXRz
pSqMZk7hCsFdf2ZbLr8SG7DiVBfybWUUWS8CAwEAAQJBALjwhUnfnZOzLbP5joek
fo1lRqCssu3zA4McV9DHYsHyP+Fc8RNsPHdGTej7UsYLTgs8YnR3bpqMHZIBPzBy
dBECIQDPn3pSKuGz1382C1e7XSobK0sMrXitwNH3IgL8A9u+uQIhAPAfRkVsLI/6
DHa9dT8UpAvlKsnhSO12dpx8cxJ0PyMnAiEAs3Mfgk1V7t7fMJL1LRgFAJ6Wq0pz
95mk4HkhIzkigOECIEwrT4o0D0q4of2Eic2xyXvwfQs/CHgzLNrk60e+UkzfAiEA
zpD+LoX8Llj+jzlKvw7OHWgkoEsuJTYAFBXbmfUipNs=
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

func TestMarshalSecret(t *testing.T) {
	tu.SetT(t)

	// create signer
	secret, _ := base64.StdEncoding.DecodeString(RSA_KEY_SECRET)
	signer := tu.NoErr(sig.ParseRsa(RSA_KEY_NAME, secret))

	// encode signer secret
	wire := tu.NoErr(sig.MarshalSecret(signer))

	// check output data
	data, _, err := spec.Spec{}.ReadData(enc.NewFastReader(wire))
	require.NoError(t, err)
	require.Equal(t, ndn.ContentTypeSigKey, *data.ContentType())
	require.Equal(t, RSA_KEY_NAME, data.Name())
	require.Equal(t, secret, data.Content().Join())
}

func TestUnmarshalSecret(t *testing.T) {
	tu.SetT(t)

	// get static secret data
	dataRaw := tu.NoErr(base64.StdEncoding.DecodeString(RSA_KEY_DATA))
	data, _, err := spec.Spec{}.ReadData(enc.NewFastBufReader(dataRaw))
	require.NoError(t, err)

	signer, err := sig.UnmarshalSecret(data)
	require.NoError(t, err)

	// check output signer
	require.Equal(t, ndn.SignatureSha256WithRsa, signer.Type())
	require.Equal(t, RSA_KEY_NAME, signer.KeyName())
}
