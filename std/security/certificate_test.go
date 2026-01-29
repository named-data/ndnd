package security_test

import (
	"encoding/base64"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/signer"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests that the `SignCert` function correctly returns an error when invoked with a nil signer and nil data.
func TestSignCertInvalid(t *testing.T) {
	tu.SetT(t)

	_, err := sec.SignCert(sec.SignCertArgs{
		Signer:   nil,
		Data:     nil,
		IssuerId: ISSUER,
	})
	require.Error(t, err)
}

// (AI GENERATED DESCRIPTION): Verifies that a key can self‑sign its own certificate, checking the certificate name, public‑key content, validity period, and Ed25519 signature correctness.
func TestSignCertSelf(t *testing.T) {
	tu.SetT(t)

	aliceKey, _ := base64.StdEncoding.DecodeString(KEY_ALICE)
	aliceKeyData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferView(aliceKey))
	aliceSigner := tu.NoErr(signer.UnmarshalSecret(aliceKeyData))

	// self-sign alice's key
	aliceCert, err := sec.SignCert(sec.SignCertArgs{
		Signer:    aliceSigner,
		Data:      aliceKeyData,
		IssuerId:  ISSUER,
		NotBefore: T1,
		NotAfter:  T2,
	})
	require.NoError(t, err)
	cert, certSigCov, err := spec_2022.Spec{}.ReadData(enc.NewWireView(aliceCert))
	require.NoError(t, err)

	// check certificate name
	name := cert.Name()
	require.True(t, KEY_ALICE_NAME.IsPrefix(name))
	require.Equal(t, len(KEY_ALICE_NAME)+2, len(name))
	require.True(t, name.At(-1).IsVersion())
	require.Greater(t, name.At(-1).NumberVal(), uint64(0))
	require.Equal(t, ISSUER, name.At(-2))

	// check data content is public key
	require.Equal(t, ndn.ContentTypeKey, cert.ContentType().Unwrap())
	alicePub := tu.NoErr(aliceSigner.Public())
	require.Equal(t, alicePub, cert.Content().Join())

	// check signature format
	signature := cert.Signature()
	require.Equal(t, ndn.SignatureEd25519, signature.SigType())
	require.Equal(t, aliceSigner.KeyName(), signature.KeyName())

	// check validity period
	notBefore, notAfter := signature.Validity()
	require.Equal(t, T1, notBefore.Unwrap())
	require.Equal(t, T2, notAfter.Unwrap())

	// check signature
	require.Equal(t, 64, len(signature.SigValue())) // ed25519
	require.True(t, tu.NoErr(signer.ValidateData(cert, certSigCov, cert)))
}

// (AI GENERATED DESCRIPTION): Verifies that Alice’s signer can correctly sign a root certificate, producing a certificate with the expected name, content, signature format, validity period, and that the signature verifies against Alice’s own certificate.
func TestSignCertOther(t *testing.T) {
	tu.SetT(t)

	aliceKey, _ := base64.StdEncoding.DecodeString(KEY_ALICE)
	aliceKeyData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferView(aliceKey))
	aliceSigner := tu.NoErr(signer.UnmarshalSecret(aliceKeyData))

	// self signed alice's key
	aliceCertWire, err := sec.SignCert(sec.SignCertArgs{
		Signer:    aliceSigner,
		Data:      aliceKeyData,
		IssuerId:  ISSUER,
		NotBefore: T1,
		NotAfter:  T2,
	})
	require.NoError(t, err)
	aliceCertData, _, err := spec_2022.Spec{}.ReadData(enc.NewWireView(aliceCertWire))
	require.NoError(t, err)

	// parse existing certificate
	rootCert, _ := base64.StdEncoding.DecodeString(CERT_ROOT)
	rootCertData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferView(rootCert))

	// sign root cert with alice's key
	newCertB, err := sec.SignCert(sec.SignCertArgs{
		Signer:    aliceSigner,
		Data:      rootCertData,
		IssuerId:  ISSUER,
		NotBefore: T1,
		NotAfter:  T2,
	})
	require.NoError(t, err)
	newCert, newSigCov, err := spec_2022.Spec{}.ReadData(enc.NewWireView(newCertB))
	require.NoError(t, err)

	// check certificate name
	name := newCert.Name()
	require.True(t, KEY_ROOT_NAME.IsPrefix(name))
	require.Equal(t, len(KEY_ROOT_NAME)+2, len(name))
	require.True(t, name.At(-1).IsVersion())
	require.Greater(t, name.At(-1).NumberVal(), uint64(0))
	require.Equal(t, ISSUER, name.At(-2))

	// check data content is public key
	require.Equal(t, ndn.ContentTypeKey, newCert.ContentType().Unwrap())
	rootPub := rootCertData.Content().Join()
	require.Equal(t, rootPub, newCert.Content().Join())

	// check signature format
	signature := newCert.Signature()
	require.Equal(t, ndn.SignatureEd25519, signature.SigType())
	require.Equal(t, aliceSigner.KeyName(), signature.KeyName())

	// check validity period
	notBefore, notAfter := signature.Validity()
	require.Equal(t, T1, notBefore.Unwrap())
	require.Equal(t, T2, notAfter.Unwrap())

	// check signature
	require.Equal(t, 64, len(signature.SigValue())) // ed25519
	require.True(t, tu.NoErr(signer.ValidateData(newCert, newSigCov, aliceCertData)))
}

func TestSignCertWithSignerCertName(t *testing.T) {
	tu.SetT(t)

	aliceKey, _ := base64.StdEncoding.DecodeString(KEY_ALICE)
	aliceKeyData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferView(aliceKey))
	aliceSigner := tu.NoErr(signer.UnmarshalSecret(aliceKeyData))

	// self signed alice's key to obtain a certificate name for the KeyLocator
	aliceCertWire := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    aliceSigner,
		Data:      aliceKeyData,
		IssuerId:  ISSUER,
		NotBefore: T1,
		NotAfter:  T2,
	}))
	aliceCertData, _, _ := spec_2022.Spec{}.ReadData(enc.NewWireView(aliceCertWire))

	// parse existing certificate
	rootCert, _ := base64.StdEncoding.DecodeString(CERT_ROOT)
	rootCertData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferView(rootCert))

	// sign root cert with alice's key but force the KeyLocator to use alice's cert name
	newCertB := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    aliceSigner,
		Data:      rootCertData,
		IssuerId:  ISSUER,
		NotBefore: T1,
		NotAfter:  T2,
	}))
	newCert, newSigCov, err := spec_2022.Spec{}.ReadData(enc.NewWireView(newCertB))
	require.NoError(t, err)

	signature := newCert.Signature()
	require.Equal(t, aliceSigner.KeyName(), signature.KeyName())
	require.True(t, tu.NoErr(signer.ValidateData(newCert, newSigCov, aliceCertData)))
}

func TestEncodeDecodeCertList(t *testing.T) {
	tu.SetT(t)
	n1 := tu.NoErr(enc.NameFromStr("/ndn/alice/KEY/aa/self/v=1"))
	n2 := tu.NoErr(enc.NameFromStr("/ndn/alice/KEY/bb/ndn/v=2"))

	wire, err := sec.EncodeCertList([]enc.Name{n1, n2})
	require.NoError(t, err)
	decoded, err := sec.DecodeCertList(wire)
	require.NoError(t, err)
	require.Equal(t, []enc.Name{n1, n2}, decoded)

	_, err = sec.EncodeCertList(nil)
	require.Error(t, err)

	_, err = sec.DecodeCertList(enc.Wire{[]byte{0x01, 0x02}})
	require.Error(t, err)
}
