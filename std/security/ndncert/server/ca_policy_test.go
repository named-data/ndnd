package server

import (
	"crypto/sha256"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/require"
)

func TestStoreCaCertificateByFullName(t *testing.T) {
	keyName, err := enc.NameFromStr("/ndnd/ucla/KEY/site-ca")
	require.NoError(t, err)
	packetSigner, err := signer.KeygenEd25519(keyName)
	require.NoError(t, err)
	publicKey, err := packetSigner.Public()
	require.NoError(t, err)
	certName, err := enc.NameFromStr("/ndnd/ucla/KEY/site-ca/self/1")
	require.NoError(t, err)
	cert, err := spec.Spec{}.MakeData(certName, &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeKey),
	}, enc.Wire{publicKey}, packetSigner)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	require.NoError(t, storeCaCertificate(spec.Spec{}, store, cert.Wire))
	parsed, _, err := spec.Spec{}.ReadData(enc.NewWireView(cert.Wire))
	require.NoError(t, err)
	digest := sha256.Sum256(cert.Wire.Join())
	fullName := parsed.Name().Append(enc.Component{
		Typ: enc.TypeImplicitSha256DigestComponent,
		Val: digest[:],
	})
	stored, err := store.Get(fullName, false)
	require.NoError(t, err)
	require.Equal(t, cert.Wire.Join(), stored)
}

func TestValidateCertRequestPolicy(t *testing.T) {
	ca := newPolicyTestCA(t)
	code, info := validatePolicyTestRequest(t, ca, "/ndnd/ucla/person")
	require.Zero(t, code, info)

	code, _ = validatePolicyTestRequest(t, ca, "/ndnd/arizona/person")
	require.Equal(t, uint64(5), code)

	code, _ = validatePolicyTestRequest(t, ca, "/ndnd/ucla/a/b/c/d/e/f")
	require.Equal(t, uint64(5), code)
}

func newPolicyTestCA(t *testing.T) *CaServer {
	caPrefix, err := enc.NameFromStr("/ndnd/ucla")
	require.NoError(t, err)
	return &CaServer{
		caPrefix: caPrefix,
		config:   &CaConfig{MaxValidityPeriod: "3600"},
		caProfile: &tlv.CaProfile{
			MaxSuffixLength: optional.Some(uint64(5)),
		},
	}
}

func validatePolicyTestRequest(t *testing.T, ca *CaServer, identity string) (uint64, string) {
	t.Helper()
	identityName, err := enc.NameFromStr(identity)
	require.NoError(t, err)
	keyName := identityName.Append(enc.NewGenericComponent("KEY"), enc.NewGenericComponent("test-key"))
	packetSigner, err := signer.KeygenEd25519(keyName)
	require.NoError(t, err)
	publicKey, err := packetSigner.Public()
	require.NoError(t, err)
	now := time.Now()
	certName := keyName.Append(enc.NewGenericComponent("self"), enc.NewVersionComponent(1))
	certWire, err := spec.Spec{}.MakeData(certName, &ndn.DataConfig{
		ContentType:  optional.Some(ndn.ContentTypeKey),
		SigNotBefore: optional.Some(now.Add(-30 * time.Second)),
		SigNotAfter:  optional.Some(now.Add(2 * time.Minute)),
	}, enc.Wire{publicKey}, packetSigner)
	require.NoError(t, err)
	certData, certSigCovered, err := spec.Spec{}.ReadData(enc.NewWireView(certWire.Wire))
	require.NoError(t, err)
	interestWire, err := spec.Spec{}.MakeInterest(
		ca.caPrefix.Append(enc.NewGenericComponent("CA"), enc.NewGenericComponent("NEW")),
		&ndn.InterestConfig{},
		enc.Wire{[]byte("new request")},
		packetSigner,
	)
	require.NoError(t, err)
	interest, interestSigCovered, err := spec.Spec{}.ReadInterest(enc.NewWireView(interestWire.Wire))
	require.NoError(t, err)
	return ca.validateCertRequest(certData, certSigCovered, interest, interestSigCovered)
}
