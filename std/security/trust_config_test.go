package security_test

import (
	"crypto/elliptic"
	"strings"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/security/trust_schema"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

/*
#site: "test"
#packet: #site/username/_ <= #user
#adminpacket: #site/admin/username/_ <= #admin

#root: #site/#KEY
#user: #site/username/#KEY <= #root
#admin: #site/admin/username/#KEY <= #root

#KEY: "KEY"/_/_/_
*/
var TRUST_CONFIG_TEST_LVS = []byte{
	0x61, 0x04, 0x00, 0x01, 0x10, 0x00, 0x25, 0x01, 0x00, 0x69, 0x01, 0x02,
	0x63, 0x1c, 0x25, 0x01, 0x00, 0x51, 0x0a, 0x25, 0x01, 0x01, 0x21, 0x05,
	0x08, 0x03, 0x4b, 0x45, 0x59, 0x51, 0x0b, 0x25, 0x01, 0x05, 0x21, 0x06,
	0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x63, 0x0e, 0x25, 0x01, 0x01, 0x57,
	0x01, 0x00, 0x53, 0x06, 0x25, 0x01, 0x02, 0x23, 0x01, 0x03, 0x63, 0x0e,
	0x25, 0x01, 0x02, 0x57, 0x01, 0x01, 0x53, 0x06, 0x25, 0x01, 0x03, 0x23,
	0x01, 0x04, 0x63, 0x0e, 0x25, 0x01, 0x03, 0x57, 0x01, 0x02, 0x53, 0x06,
	0x25, 0x01, 0x04, 0x23, 0x01, 0x05, 0x63, 0x0c, 0x25, 0x01, 0x04, 0x57,
	0x01, 0x03, 0x29, 0x04, 0x23, 0x4b, 0x45, 0x59, 0x63, 0x29, 0x25, 0x01,
	0x05, 0x57, 0x01, 0x00, 0x29, 0x05, 0x23, 0x73, 0x69, 0x74, 0x65, 0x51,
	0x0a, 0x25, 0x01, 0x06, 0x21, 0x05, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x53,
	0x06, 0x25, 0x01, 0x0a, 0x23, 0x01, 0x01, 0x53, 0x06, 0x25, 0x01, 0x10,
	0x23, 0x01, 0x02, 0x63, 0x0e, 0x25, 0x01, 0x06, 0x57, 0x01, 0x05, 0x53,
	0x06, 0x25, 0x01, 0x07, 0x23, 0x01, 0x06, 0x63, 0x0e, 0x25, 0x01, 0x07,
	0x57, 0x01, 0x06, 0x53, 0x06, 0x25, 0x01, 0x08, 0x23, 0x01, 0x07, 0x63,
	0x0e, 0x25, 0x01, 0x08, 0x57, 0x01, 0x07, 0x53, 0x06, 0x25, 0x01, 0x09,
	0x23, 0x01, 0x08, 0x63, 0x0d, 0x25, 0x01, 0x09, 0x57, 0x01, 0x08, 0x29,
	0x05, 0x23, 0x72, 0x6f, 0x6f, 0x74, 0x63, 0x1a, 0x25, 0x01, 0x0a, 0x57,
	0x01, 0x05, 0x51, 0x0a, 0x25, 0x01, 0x0b, 0x21, 0x05, 0x08, 0x03, 0x4b,
	0x45, 0x59, 0x53, 0x06, 0x25, 0x01, 0x0f, 0x23, 0x01, 0x0c, 0x63, 0x0e,
	0x25, 0x01, 0x0b, 0x57, 0x01, 0x0a, 0x53, 0x06, 0x25, 0x01, 0x0c, 0x23,
	0x01, 0x09, 0x63, 0x0e, 0x25, 0x01, 0x0c, 0x57, 0x01, 0x0b, 0x53, 0x06,
	0x25, 0x01, 0x0d, 0x23, 0x01, 0x0a, 0x63, 0x0e, 0x25, 0x01, 0x0d, 0x57,
	0x01, 0x0c, 0x53, 0x06, 0x25, 0x01, 0x0e, 0x23, 0x01, 0x0b, 0x63, 0x10,
	0x25, 0x01, 0x0e, 0x57, 0x01, 0x0d, 0x29, 0x05, 0x23, 0x75, 0x73, 0x65,
	0x72, 0x55, 0x01, 0x09, 0x63, 0x12, 0x25, 0x01, 0x0f, 0x57, 0x01, 0x0a,
	0x29, 0x07, 0x23, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x55, 0x01, 0x0e,
	0x63, 0x0e, 0x25, 0x01, 0x10, 0x57, 0x01, 0x05, 0x53, 0x06, 0x25, 0x01,
	0x11, 0x23, 0x01, 0x01, 0x63, 0x1a, 0x25, 0x01, 0x11, 0x57, 0x01, 0x10,
	0x51, 0x0a, 0x25, 0x01, 0x12, 0x21, 0x05, 0x08, 0x03, 0x4b, 0x45, 0x59,
	0x53, 0x06, 0x25, 0x01, 0x16, 0x23, 0x01, 0x10, 0x63, 0x0e, 0x25, 0x01,
	0x12, 0x57, 0x01, 0x11, 0x53, 0x06, 0x25, 0x01, 0x13, 0x23, 0x01, 0x0d,
	0x63, 0x0e, 0x25, 0x01, 0x13, 0x57, 0x01, 0x12, 0x53, 0x06, 0x25, 0x01,
	0x14, 0x23, 0x01, 0x0e, 0x63, 0x0e, 0x25, 0x01, 0x14, 0x57, 0x01, 0x13,
	0x53, 0x06, 0x25, 0x01, 0x15, 0x23, 0x01, 0x0f, 0x63, 0x11, 0x25, 0x01,
	0x15, 0x57, 0x01, 0x14, 0x29, 0x06, 0x23, 0x61, 0x64, 0x6d, 0x69, 0x6e,
	0x55, 0x01, 0x09, 0x63, 0x17, 0x25, 0x01, 0x16, 0x57, 0x01, 0x11, 0x29,
	0x0c, 0x23, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x70, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x55, 0x01, 0x15, 0x67, 0x0d, 0x23, 0x01, 0x01, 0x29, 0x08, 0x75,
	0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x67, 0x0a, 0x23, 0x01, 0x02,
	0x29, 0x05, 0x61, 0x64, 0x6d, 0x69, 0x6e,
}

// Helper to create a name
func sname(n string) enc.Name {
	return tu.NoErr(enc.NameFromStr(n))
}

// Helper to sign a certificate
func signCert(signer ndn.Signer, wire enc.Wire) (enc.Wire, ndn.Data) {
	data, _, _ := spec.Spec{}.ReadData(enc.NewFastReader(wire))
	cert, _ := sec.SignCert(sec.SignCertArgs{
		Signer:    signer,
		Data:      data,
		IssuerId:  enc.NewGenericComponent("ndn"),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	})
	certData, _, _ := spec.Spec{}.ReadData(enc.NewFastReader(cert))
	return cert, certData
}

// This is intended as the ultimate trust config test.
func testTrustConfig(t *testing.T, keychain ndn.KeyChain, schema ndn.TrustSchema) {
	network := make(map[string]enc.Wire)

	// ------------- Keys and certs -------------
	// Root key
	rootSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test")))
	rootCertWire, rootCertData := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(rootSigner)))
	network[rootCertData.Name().String()] = rootCertWire
	keychain.InsertCert(rootCertWire.Join())

	// Second root key
	root2Signer, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test")))
	root2CertWire, root2CertData := signCert(root2Signer, tu.NoErr(signer.MarshalSecret(root2Signer)))
	network[root2CertData.Name().String()] = root2CertWire
	keychain.InsertCert(root2CertWire.Join())

	// Alice key (us)
	aliceSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/alice")))
	aliceCertWire, aliceCertData := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(aliceSigner)))
	network[aliceCertData.Name().String()] = aliceCertWire
	keychain.InsertCert(aliceCertWire.Join())
	keychain.InsertKey(aliceSigner)

	// Alice key invalid (same name but different key)
	aliceInvalidSigner, _ := signer.KeygenEd25519(aliceSigner.KeyName())
	require.Equal(t, aliceSigner.KeyName(), aliceInvalidSigner.KeyName())

	// Alice admin key
	aliceAdminSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/admin/alice")))
	aliceAdminCertWire, aliceAdminCertData := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(aliceAdminSigner)))
	network[aliceAdminCertData.Name().String()] = aliceAdminCertWire
	keychain.InsertCert(aliceAdminCertWire.Join())
	keychain.InsertKey(aliceAdminSigner)

	// Bob key
	bobSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/bob")))
	bobCertWire, bobCertData := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(bobSigner)))
	network[bobCertData.Name().String()] = bobCertWire
	// Bob is not present in the keychain

	// Cathy key (also us)
	cathySigner, _ := signer.KeygenEcc(sec.MakeKeyName(sname("/test/cathy")), elliptic.P384())
	cathyCertWire, cathyCertData := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(cathySigner)))
	network[cathyCertData.Name().String()] = cathyCertWire
	keychain.InsertCert(cathyCertWire.Join())
	keychain.InsertKey(cathySigner)

	// David key
	davidSigner, _ := signer.KeygenRsa(sec.MakeKeyName(sname("/test/david")), 1024)
	// David is not present in the keychain *or network*

	// Fred's key is signed with the second root
	fredSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/fred")))
	fredCertBytes, fredCertData := signCert(root2Signer, tu.NoErr(signer.MarshalSecret(fredSigner)))
	network[fredCertData.Name().String()] = fredCertBytes
	// Fred is not present in the keychain
	// -----------------------------------

	// ------------- Mallory -------------
	// Mallory root key
	malloryRootSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test")))
	malloryRootCertWire, malloryRootCertData := signCert(malloryRootSigner, tu.NoErr(signer.MarshalSecret(malloryRootSigner)))
	network[malloryRootCertData.Name().String()] = malloryRootCertWire

	// Mallory key
	mallorySigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/mallory")))
	malloryCertWire, malloryCertData := signCert(malloryRootSigner, tu.NoErr(signer.MarshalSecret(mallorySigner)))
	network[malloryCertData.Name().String()] = malloryCertWire

	// Mallory Alice key
	mAliceSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/alice")))
	mAliceCertWire, mAliceCertData := signCert(malloryRootSigner, tu.NoErr(signer.MarshalSecret(mAliceSigner)))
	network[mAliceCertData.Name().String()] = mAliceCertWire
	// -----------------------------------

	// Simulate fetch from network using engine
	fetchCount := 0
	fetch := func(name enc.Name, _ *ndn.InterestConfig, callback ndn.ExpressCallbackFunc) {
		fetchCount++
		for certName, certWire := range network {
			if strings.HasPrefix(certName, name.String()) {
				data, sigCov, err := spec.Spec{}.ReadData(enc.NewFastReader(certWire))
				callback(ndn.ExpressCallbackArgs{
					Result:     ndn.InterestResultData,
					Data:       data,
					RawData:    certWire,
					SigCovered: sigCov,
					Error:      err,
				})
				return
			}
		}
		callback(ndn.ExpressCallbackArgs{
			Result: ndn.InterestResultNack,
		})
	}

	// Create trust config
	trust, err := sec.NewTrustConfig(
		keychain,
		schema,
		[]enc.Name{
			rootCertData.Name(),
			root2CertData.Name(),
		})
	require.NoError(t, err)

	// Test key suggestion
	require.Equal(t, aliceSigner.KeyName(), trust.Suggest(sname("/test/alice/data1")).KeyName())
	require.Equal(t, aliceSigner.KeyName(), trust.Suggest(sname("/test/alice/data2")).KeyName())
	require.Equal(t, aliceAdminSigner.KeyName(), trust.Suggest(sname("/test/admin/alice/data3")).KeyName())
	require.Equal(t, nil, trust.Suggest(sname("/test/bob/data")))
	require.Equal(t, cathySigner.KeyName(), trust.Suggest(sname("/test/cathy/data")).KeyName())
	require.Equal(t, nil, trust.Suggest(sname("/test/root/data")))

	// Sign data with alice key matching schema
	validateSync := func(name string, signer ndn.Signer) bool {
		content := enc.Wire{[]byte{0x01, 0x02, 0x03}}
		dataW, err := spec.Spec{}.MakeData(sname(name), &ndn.DataConfig{}, content, signer)
		require.NoError(t, err)
		data, sigCov, err := spec.Spec{}.ReadData(enc.NewFastReader(dataW.Wire))
		require.NoError(t, err)
		ch := make(chan bool)
		go trust.Validate(sec.TrustConfigValidateArgs{
			Data:       data,
			DataSigCov: sigCov,
			Fetch:      fetch,
			Callback:   func(valid bool, err error) { ch <- valid },
		})
		return <-ch
	}

	// Signing with correct keys
	fetchCount = 0
	require.True(t, validateSync("/test/alice/data1", aliceSigner))
	require.Equal(t, 0, fetchCount) // have all certificates
	require.True(t, validateSync("/test/bob/data1", bobSigner))
	require.Equal(t, 1, fetchCount) // fetch bob's certificate
	require.True(t, validateSync("/test/bob/data2", bobSigner))
	require.Equal(t, 1, fetchCount) // cert in store
	require.True(t, validateSync("/test/cathy/data1", cathySigner))
	require.Equal(t, 1, fetchCount) // have all certificates

	// Signing with admin key
	require.True(t, validateSync("/test/admin/alice/data1", aliceAdminSigner))

	// Invalid signer (different key)
	require.False(t, validateSync("/test/alice/data1", aliceInvalidSigner))

	// Sign with cert that cannot be fetched
	fetchCount = 0
	require.False(t, validateSync("/test/david/data1", davidSigner))
	require.Equal(t, 1, fetchCount) // fetch david's certificate

	// Test multiple root certificates
	fetchCount = 0
	require.True(t, validateSync("/test/fred/data1", fredSigner))
	require.Equal(t, 1, fetchCount) // fetch fred's certificate

	// Sign with incorrect key
	require.False(t, validateSync("/test/alice/data1", bobSigner))
	require.False(t, validateSync("/test/alice/data1", aliceAdminSigner))
	require.False(t, validateSync("/test/admin/alice/data1", aliceSigner))
	require.False(t, validateSync("/test/bob/data1", aliceSigner))
	require.False(t, validateSync("/test/admin/bob/data1", aliceAdminSigner))

	// Sign with incorrect naming
	require.False(t, validateSync("/test/alice/data1/extra", aliceSigner))
	require.False(t, validateSync("/test/bob", bobSigner))
	require.False(t, validateSync("/hello/alice/data1", aliceSigner))

	// Sign with root certificate
	require.False(t, validateSync("/test/alice/data1", rootSigner))

	// Sign with mallory's malicious keys
	fetchCount = 0
	require.False(t, validateSync("/test/alice/data3", mAliceSigner))
	require.Equal(t, 2, fetchCount) // fetch 2x mallory certs
	require.False(t, validateSync("/test/alice/data4", mAliceSigner))
	require.Equal(t, 4, fetchCount) // invalid cert not in store
	require.False(t, validateSync("/test/alice/data3", malloryRootSigner))
	require.Equal(t, 5, fetchCount) // fetch 1x mallory cert
	require.False(t, validateSync("/test/alice/data/extra", mallorySigner))
	require.Equal(t, 6, fetchCount) // don't bother fetching mallory root because of schema miss
	require.False(t, validateSync("/test/mallory/data4", mallorySigner))
}

func TestTrustConfigLvs(t *testing.T) {
	tu.SetT(t)

	store := object.NewMemoryStore()
	keychain := keychain.NewKeyChainMem(store)
	schema, err := trust_schema.NewLvsSchema(TRUST_CONFIG_TEST_LVS)
	require.NoError(t, err)

	testTrustConfig(t, keychain, schema)
}
