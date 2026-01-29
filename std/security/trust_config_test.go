package security_test

import (
	"crypto/elliptic"
	_ "embed"
	"fmt"
	"math"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/security/trust_schema"
	"github.com/named-data/ndnd/std/types/optional"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

/*
#site: "test"
#packet: #site/username/_ <= #user
#adminpacket: #site/admin/username/_ <= #admin

#invitee_packet: #site/username/app/#site/invitee/_ <= #user

#root: #site/#KEY
#user: #site/username/#KEY <= #root
#admin: #site/admin/username/#KEY <= #root

#KEY: "KEY"/_/_/_
*/
//go:embed trust_config_test_lvs_intra.tlv
var TRUST_CONFIG_INTRA_LVS []byte

/*
#testbed: "root"
#wksp: "app"
#KEY: "KEY"/_/_/_
#CL: "KEY"/_/"32=auth"/_

#root: #testbed/#KEY                     <= #root
#owner: #testbed/"owner"/#KEY            <= #root
#anchorpre: #wksp/#KEY                   <= #owner
#anchor: #wksp/#KEY                      <= #anchor         // workspace trust anchor (self-signed)
#anchorcl: #wksp/#CL                     <= #anchor

#usercert: #wksp/"user"/user/#KEY        <= #anchor
#userdata: #wksp/"user"/user/_           <= #usercert

*/
//go:embed trust_config_test_lvs_inter.tlv
var TRUST_CONFIG_INTER_LVS []byte

// Helper to create a name
func sname(n string) enc.Name {
	return tu.NoErr(enc.NameFromStr(n))
}

// Helper to sign a certificate
type SignCertOptions struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// (AI GENERATED DESCRIPTION): Creates a signed certificate for the supplied Data packet using the provided signer, and returns the certificate wire, its content, and the signature‑covered portion.
func signCert(signer ndn.Signer, wire enc.Wire, opts SignCertOptions) (enc.Wire, ndn.Data, enc.Wire) {
	data, _, _ := spec.Spec{}.ReadData(enc.NewWireView(wire))
	cert, _ := sec.SignCert(sec.SignCertArgs{
		Signer:    signer,
		Data:      data,
		IssuerId:  enc.NewGenericComponent("ndn"),
		NotBefore: opts.NotBefore,
		NotAfter:  opts.NotAfter,
	})
	certData, sigCovered, _ := spec.Spec{}.ReadData(enc.NewWireView(cert))
	return cert, certData, sigCovered
}

// Current test items
var tcTestT *testing.T = nil
var tcTestTrustConfig *sec.TrustConfig = nil
var tcTestNetwork map[string]enc.Wire = make(map[string]enc.Wire)
var tcTestKeyChain ndn.KeyChain = nil
var tcTestFetchCount int = 0

type ValidateSyncOptions struct {
	name           string
	signer         ndn.Signer
	crossSchema    enc.Wire
	ignoreValidity bool
}

// Helper to validate a packet synchronously
func validateSync(opts ValidateSyncOptions) bool {
	content := enc.Wire{[]byte{0x01, 0x02, 0x03}}
	dataW, err := spec.Spec{}.MakeData(sname(opts.name), &ndn.DataConfig{
		CrossSchema: opts.crossSchema,
	}, content, opts.signer)
	require.NoError(tcTestT, err)
	data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(dataW.Wire))
	require.NoError(tcTestT, err)
	ch := make(chan bool)
	go tcTestTrustConfig.Validate(sec.TrustConfigValidateArgs{
		Data:       data,
		DataSigCov: sigCov,
		Fetch:      fetchFun,
		Callback: func(valid bool, err error) {
			tcTestT.Log("Validation", opts.name, valid, err)
			ch <- valid
			close(ch)
		},
		IgnoreValidity: optional.Some(opts.ignoreValidity),
	})
	return <-ch
}

// Helper to validate certificates
func validateCerts(certData ndn.Data, certDataSigCov enc.Wire, ignoreValidity bool) bool {
	ch := make(chan bool)
	go tcTestTrustConfig.Validate(sec.TrustConfigValidateArgs{
		Data:       certData,
		DataSigCov: certDataSigCov,
		Fetch:      fetchFun,
		Callback: func(valid bool, err error) {
			tcTestT.Log("Validation", valid, err)
			ch <- valid
			close(ch)
		},
		IgnoreValidity: optional.Some(ignoreValidity),
	})
	return <-ch
}

// Mock network fetch function
func fetchFun(name enc.Name, cfg *ndn.InterestConfig, callback ndn.ExpressCallbackFunc) {
	// Return from local keychain if possible
	if tcTestKeyChain != nil {
		if buf, _ := tcTestKeyChain.Store().Get(name, true); buf != nil {
			data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(enc.Wire{buf}))
			callback(ndn.ExpressCallbackArgs{
				Result:     ndn.InterestResultData,
				Data:       data,
				RawData:    enc.Wire{buf},
				SigCovered: sigCov,
				Error:      err,
				IsLocal:    true,
			})
			return
		}
	}

	tcTestFetchCount++

	// Any 32=auth indicates a CertList (only for testing)
	allowAuth := false
	for _, c := range name {
		if c.IsKeyword("auth") {
			allowAuth = true
			break
		}
	}

	// Get data from dummy network
	if direct, ok := tcTestNetwork[name.String()]; ok {
		data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(direct))
		callback(ndn.ExpressCallbackArgs{
			Result:     ndn.InterestResultData,
			Data:       data,
			RawData:    direct,
			SigCovered: sigCov,
			Error:      err,
		})
		return
	}

	// Otherwise, iterate dummy network if CanBePrefix
	if cfg != nil && cfg.CanBePrefix {
		// Pick the longest prefix match among all
		bestExtra := math.MaxInt
		var best enc.Wire
		for nstr, w := range tcTestNetwork {
			nm := tu.NoErr(enc.NameFromStr(nstr))
			if !name.IsPrefix(nm) {
				continue
			}
			// Just in case we accidentally fetch CertList
			if !allowAuth && len(nm) > len(name) && nm[len(name)].IsKeyword("auth") {
				continue
			}
			extra := len(nm) - len(name)
			// Get the best match
			if best == nil || extra < bestExtra {
				bestExtra = extra
				best = w
			}
		}
		if best != nil {
			data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(best))
			callback(ndn.ExpressCallbackArgs{
				Result:     ndn.InterestResultData,
				Data:       data,
				RawData:    best,
				SigCovered: sigCov,
				Error:      err,
			})
			return
		}
	}

	// Otherwise, fall through
	callback(ndn.ExpressCallbackArgs{
		Result: ndn.InterestResultNack,
		Error: func() error {
			if allowAuth {
				return fmt.Errorf("failed to fetch CertList (%s)", name)
			}
			return fmt.Errorf("not found")
		}(),
	})
}

// This is intended as the ultimate intra-domain trust config test.
func testTrustConfigIntra(t *testing.T, schema ndn.TrustSchema) {
	clear(tcTestNetwork)
	tcTestT = t
	network := tcTestNetwork
	keychain := tcTestKeyChain
	opts := SignCertOptions{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	// ------------- Keys and certs -------------
	// Root key
	rootSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test")))
	rootCertWire, rootCertData, _ := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(rootSigner)), opts)
	network[rootCertData.Name().String()] = rootCertWire
	keychain.InsertCert(rootCertWire.Join())

	// Second root key
	root2Signer, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test")))
	root2CertWire, root2CertData, _ := signCert(root2Signer, tu.NoErr(signer.MarshalSecret(root2Signer)), opts)
	network[root2CertData.Name().String()] = root2CertWire
	keychain.InsertCert(root2CertWire.Join())

	// Alice key (us)
	aliceSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/alice")))
	aliceCertWire, aliceCertData, _ := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(aliceSigner)), opts)
	network[aliceCertData.Name().String()] = aliceCertWire
	keychain.InsertCert(aliceCertWire.Join())
	keychain.InsertKey(aliceSigner)

	// Alice key invalid (same name but different key)
	aliceInvalidSigner, _ := signer.KeygenEd25519(aliceSigner.KeyName())
	require.Equal(t, aliceSigner.KeyName(), aliceInvalidSigner.KeyName())

	// Alice admin key
	aliceAdminSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/admin/alice")))
	aliceAdminCertWire, aliceAdminCertData, _ := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(aliceAdminSigner)), opts)
	network[aliceAdminCertData.Name().String()] = aliceAdminCertWire
	keychain.InsertCert(aliceAdminCertWire.Join())
	keychain.InsertKey(aliceAdminSigner)

	// Bob key
	bobSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/bob")))
	bobCertWire, bobCertData, _ := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(bobSigner)), opts)
	network[bobCertData.Name().String()] = bobCertWire
	// Bob is not present in the keychain

	// Cathy key (also us)
	cathySigner, _ := signer.KeygenEcc(sec.MakeKeyName(sname("/test/cathy")), elliptic.P384())
	cathyCertWire, cathyCertData, _ := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(cathySigner)), opts)
	network[cathyCertData.Name().String()] = cathyCertWire
	keychain.InsertCert(cathyCertWire.Join())
	keychain.InsertKey(cathySigner)

	// David key
	davidSigner, _ := signer.KeygenRsa(sec.MakeKeyName(sname("/test/david")), 1024)
	// David is not present in the keychain *or network*

	// Fred's key is signed with the second root
	fredSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/fred")))
	fredCertBytes, fredCertData, _ := signCert(root2Signer, tu.NoErr(signer.MarshalSecret(fredSigner)), opts)
	network[fredCertData.Name().String()] = fredCertBytes
	// Fred is not present in the keychain
	// -----------------------------------

	// ------------- Mallory -------------
	// Mallory root key 1 (different key name from real root)
	malloryRootSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test")))
	malloryRootCertWire, malloryRootCertData, _ := signCert(malloryRootSigner, tu.NoErr(signer.MarshalSecret(malloryRootSigner)), opts)
	network[malloryRootCertData.Name().String()] = malloryRootCertWire

	// Mallory root key 2 (same key name as real root)
	malloryRoot2Signer, _ := signer.KeygenEd25519(rootSigner.KeyName())
	malloryRoot2CertWire, malloryRoot2CertData, _ := signCert(malloryRoot2Signer, tu.NoErr(signer.MarshalSecret(malloryRoot2Signer)), opts)
	network[malloryRoot2CertData.Name().String()] = malloryRoot2CertWire

	// Mallory key (mallory root 1)
	mallorySigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/mallory")))
	malloryCertWire, malloryCertData, _ := signCert(malloryRootSigner, tu.NoErr(signer.MarshalSecret(mallorySigner)), opts)
	network[malloryCertData.Name().String()] = malloryCertWire

	// Mallory key (mallory root 2)
	mallory2Signer, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/mallory")))
	mallory2CertWire, mallory2CertData, _ := signCert(malloryRoot2Signer, tu.NoErr(signer.MarshalSecret(mallory2Signer)), opts)
	network[mallory2CertData.Name().String()] = mallory2CertWire

	// Mallory Alice key (mallory root 1)
	mAliceSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/alice")))
	mAliceCertWire, mAliceCertData, _ := signCert(malloryRootSigner, tu.NoErr(signer.MarshalSecret(mAliceSigner)), opts)
	network[mAliceCertData.Name().String()] = mAliceCertWire

	// Mallory Alice key (mallory root 2)
	mAlice2Signer, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/alice")))
	mAlice2CertWire, mAlice2CertData, _ := signCert(malloryRoot2Signer, tu.NoErr(signer.MarshalSecret(mAlice2Signer)), opts)
	network[mAlice2CertData.Name().String()] = mAlice2CertWire
	// -----------------------------------

	// Create trust config
	trust, err := sec.NewTrustConfig(
		keychain,
		schema,
		[]enc.Name{
			rootCertData.Name(),
			root2CertData.Name(),
		})
	require.NoError(t, err)
	tcTestTrustConfig = trust

	// Test key suggestion
	require.Equal(t, aliceSigner.KeyName(), trust.Suggest(sname("/test/alice/data1")).KeyName())
	require.Equal(t, aliceSigner.KeyName(), trust.Suggest(sname("/test/alice/data2")).KeyName())
	require.Equal(t, aliceAdminSigner.KeyName(), trust.Suggest(sname("/test/admin/alice/data3")).KeyName())
	require.Equal(t, nil, trust.Suggest(sname("/test/bob/data")))
	require.Equal(t, cathySigner.KeyName(), trust.Suggest(sname("/test/cathy/data")).KeyName())
	require.Equal(t, nil, trust.Suggest(sname("/test/root/data")))

	// Signing with correct keys
	tcTestFetchCount = 0
	require.True(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data1",
		signer: aliceSigner,
	}))
	require.Equal(t, 0, tcTestFetchCount) // have all certificates
	require.True(t, validateSync(ValidateSyncOptions{
		name:   "/test/bob/data1",
		signer: bobSigner,
	}))
	require.Equal(t, 1, tcTestFetchCount) // fetch bob's certificate
	require.True(t, validateSync(ValidateSyncOptions{
		name:   "/test/bob/data2",
		signer: bobSigner,
	}))
	require.Equal(t, 1, tcTestFetchCount) // cert in cache
	require.True(t, validateSync(ValidateSyncOptions{
		name:   "/test/cathy/data1",
		signer: cathySigner,
	}))
	require.Equal(t, 1, tcTestFetchCount) // have all certificates

	// Make sure that bob's cert was inserted into the store
	if buf, _ := keychain.Store().Get(bobCertData.Name(), false); buf == nil {
		t.Error("bob's cert not in store")
	}

	// Signing with admin key
	require.True(t, validateSync(ValidateSyncOptions{
		name:   "/test/admin/alice/data1",
		signer: aliceAdminSigner,
	}))

	// Invalid signer (different key)
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data1",
		signer: aliceInvalidSigner,
	}))

	// Sign with cert that cannot be fetched
	tcTestFetchCount = 0
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/david/data1",
		signer: davidSigner,
	}))
	require.Equal(t, 1, tcTestFetchCount) // fetch david's certificate

	// Test multiple root certificates
	tcTestFetchCount = 0
	require.True(t, validateSync(ValidateSyncOptions{
		name:   "/test/fred/data1",
		signer: fredSigner,
	}))
	require.Equal(t, 1, tcTestFetchCount) // fetch fred's certificate

	// Sign with incorrect key
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data1",
		signer: bobSigner,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data1",
		signer: aliceAdminSigner,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/admin/alice/data1",
		signer: aliceSigner,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/bob/data1",
		signer: aliceSigner,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/admin/bob/data1",
		signer: aliceAdminSigner,
	}))

	// Sign with incorrect naming
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data1/extra",
		signer: aliceSigner,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/bob",
		signer: bobSigner,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/hello/alice/data1",
		signer: aliceSigner,
	}))

	// Sign with root certificate
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data1",
		signer: rootSigner,
	}))

	// Sign with mallory's malicious keys (root 1)
	tcTestFetchCount = 0
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data3",
		signer: mAliceSigner,
	}))
	require.Equal(t, 3, tcTestFetchCount) // fetch 2x mallory certs + CertList
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data4",
		signer: mAliceSigner,
	}))
	require.Equal(t, 6, tcTestFetchCount) // invalid cert not in store: 3 more fetches (includes CertList)
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data3",
		signer: malloryRootSigner,
	}))
	require.Equal(t, 7, tcTestFetchCount) // fetch 1x mallory cert
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data/extra",
		signer: mallorySigner,
	}))
	require.Equal(t, 8, tcTestFetchCount) // only CertList fetched; mallory root skipped by schema
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/mallory/data4",
		signer: mallorySigner,
	}))
	require.Equal(t, 11, tcTestFetchCount) // schema hit, 3 fetches: 2x mallory certs + 1x CertList

	// Sign with mallory's malicious keys (root 2)
	// In this case the root certificate name is the same, so that cert should not be fetched
	tcTestFetchCount = 0
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data3",
		signer: mAlice2Signer,
	}))
	require.Equal(t, 1, tcTestFetchCount) // fetch mallory's alice cert
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data4",
		signer: mAlice2Signer,
	}))
	require.Equal(t, 2, tcTestFetchCount) // invalid cert not in store
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data3",
		signer: malloryRoot2Signer,
	}))
	require.Equal(t, 2, tcTestFetchCount) // nothing fetched, root cert is in store
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/data/extra",
		signer: mallory2Signer,
	}))
	require.Equal(t, 3, tcTestFetchCount) // (same as root 1)
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/mallory/data4",
		signer: mallory2Signer,
	}))
	require.Equal(t, 4, tcTestFetchCount) // (same as root 1, except no mallory root fetch)

	// ========================================================================

	// Test with cross schema validation
	// Alice signs a cross schema for bob to allow bob to publish in alice's namespace
	abInvite, err := trust_schema.SignCrossSchema(trust_schema.SignCrossSchemaArgs{
		Name:   sname("/test/alice/32=INVITE/test/bob/v=1"),
		Signer: aliceSigner,
		Content: trust_schema.CrossSchemaContent{
			SimpleSchemaRules: []*trust_schema.SimpleSchemaRule{{
				NamePrefix: sname("/test/alice/app/test/bob"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/bob/KEY")}, // any key from bob
			}},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// Bob signs a data under alice namespace
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/app/test/bob/data1",
		signer: bobSigner,
	}))
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data1",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data2",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))

	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/alice/data1",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/ndn/test/bob/data1",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data1/extra",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/data1",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))

	// Ignore the cross schema if already in the namespace
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/bob/data1",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))

	// More complex cross schema
	acInvite, err := trust_schema.SignCrossSchema(trust_schema.SignCrossSchemaArgs{
		Name:   sname("/test/alice/32=INVITE/test/cathy/v=1"),
		Signer: aliceSigner,
		Content: trust_schema.CrossSchemaContent{
			SimpleSchemaRules: []*trust_schema.SimpleSchemaRule{{
				NamePrefix: sname("/test/alice/app/test/cathy"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/cathy/KEY")},
			}, {
				NamePrefix: sname("/test/alice/app/test/cathy-2"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/cathy/KEY")},
			}, {
				NamePrefix: sname("/test/alice/app/test/bob/data-5"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/cathy/KEY")},
			}, {
				NamePrefix: sname("/test/alice/app/test/bob/data-7"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/bob/KEY")},
			}, {
				NamePrefix: sname("/test/david/app/test/cathy"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/cathy/KEY")},
			}, {
				NamePrefix: sname("/hello"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/cathy/KEY")},
			}},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// Cathy signs a data under alice namespace
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/data1",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/data1",
		signer:      cathySigner,
		crossSchema: abInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/data1",
		signer:      bobSigner,
		crossSchema: abInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/data1",
		signer:      bobSigner,
		crossSchema: acInvite,
	}))

	// Cathy is allowed a second namespace
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy-2/data1",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy-3/data1",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))

	// Cathy is allowed to publish in alice-bob namespace for a specific data
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data-5",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data-6",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))

	// Rules can have different key locators
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data-7",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data-7",
		signer:      bobSigner,
		crossSchema: acInvite,
	}))

	// Alice allowed cathy to publish in david's namespace
	// But Alice is not allowed to publish in david's namespace
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/david/app/test/cathy/data1",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))

	// Impossible namespaces
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/hello",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/hello/data1",
		signer:      cathySigner,
		crossSchema: acInvite,
	}))

	// Schema with a blanket prefix rule
	apInvite, err := trust_schema.SignCrossSchema(trust_schema.SignCrossSchemaArgs{
		Name:   sname("/test/alice/32=INVITE/test/bob/v=1"),
		Signer: aliceSigner,
		Content: trust_schema.CrossSchemaContent{
			PrefixSchemaRules: []*trust_schema.PrefixSchemaRule{{
				NamePrefix: sname("/test/alice/app"),
			}},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// Anyone can form their own sub-namespace within alice's app namespace
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data1",
		signer:      bobSigner,
		crossSchema: apInvite,
	}))
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/data1",
		signer:      cathySigner,
		crossSchema: apInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/data1",
		signer:      bobSigner,
		crossSchema: apInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/david/app/test/bob/data1",
		signer:      bobSigner,
		crossSchema: apInvite,
	}))

	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/data1",
		signer:      aliceSigner,
		crossSchema: apInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/data1",
		signer:      bobSigner,
		crossSchema: apInvite,
	}))

	// Component-based rule: capture producer id between prefix and key name
	acCollabInvite, err := trust_schema.SignCrossSchema(trust_schema.SignCrossSchemaArgs{
		Name:   sname("/test/alice/32=INVITE/test/component/v=1"),
		Signer: aliceSigner,
		Content: trust_schema.CrossSchemaContent{
			ComponentSchemaRules: []*trust_schema.ComponentSchemaRule{{
				NamePrefix:         sname("/test/alice/app/test"),
				KeyLocator:         &spec.KeyLocator{Name: sname("/test")},
				NameComponentIndex: 4, // /test alice app test bob -> capture "bob"
				KeyComponentIndex:  1, // /test bob KEY...
			}},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// Bob cannot sign in alice namespace without the cross schema
	require.False(t, validateSync(ValidateSyncOptions{
		name:   "/test/alice/app/test/bob/component1",
		signer: bobSigner,
	}))

	// Bob and Cathy can publish if their id appears in the captured position
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/component1",
		signer:      bobSigner,
		crossSchema: acCollabInvite,
	}))
	require.True(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/component2",
		signer:      cathySigner,
		crossSchema: acCollabInvite,
	}))

	// Mismatched captured component is rejected
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/cathy/component2",
		signer:      bobSigner,
		crossSchema: acCollabInvite,
	}))
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test",
		signer:      cathySigner,
		crossSchema: acCollabInvite,
	}))

	// Malicious cross schema created by bob for bob
	bobMCross, err := trust_schema.SignCrossSchema(trust_schema.SignCrossSchemaArgs{
		Name:   sname("/test/alice/32=INVITE/test/bob/v=1"),
		Signer: bobSigner,
		Content: trust_schema.CrossSchemaContent{
			SimpleSchemaRules: []*trust_schema.SimpleSchemaRule{{
				NamePrefix: sname("/test/alice/app/test/bob"),
				KeyLocator: &spec.KeyLocator{Name: sname("/test/bob/KEY")}, // any key from bob
			}},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// This cross schema should not be accepted
	require.False(t, validateSync(ValidateSyncOptions{
		name:        "/test/alice/app/test/bob/data1",
		signer:      bobSigner,
		crossSchema: bobMCross,
	}))

	// ------------- Eve (certificates only) -------------
	expiredOpts := SignCertOptions{
		NotBefore: time.Now().Add(-2 * time.Hour), // 2 hours ago
		NotAfter:  time.Now().Add(-1 * time.Hour), // 1 hour ago
	}
	eveSigner, _ := signer.KeygenEd25519(sec.MakeKeyName(sname("/test/eve")))
	tcTestT.Log(eveSigner.KeyLocator().String())
	eveCertWire, eveCertData, eveSigCov := signCert(rootSigner, tu.NoErr(signer.MarshalSecret(eveSigner)), expiredOpts)
	network[eveCertData.Name().String()] = eveCertWire
	require.False(t, validateCerts(eveCertData, eveSigCov, false))
	require.True(t, validateCerts(eveCertData, eveSigCov, true))
	require.False(t, validateSync(ValidateSyncOptions{
		name:           "/test/eve/data1",
		signer:         eveSigner,
		ignoreValidity: false,
	}))
	require.True(t, validateSync(ValidateSyncOptions{
		name:           "/test/eve/data2",
		signer:         eveSigner,
		ignoreValidity: true,
	}))
}

// This is intended as the ultimate inter-domain trust config test.
func testTrustConfigInter(t *testing.T, schema ndn.TrustSchema) {
	clear(tcTestNetwork)
	tcTestT = t
	network := tcTestNetwork

	now := time.Now()
	nb := now.Add(-time.Minute)
	na := now.Add(time.Hour)
	n := func(s string) enc.Name { return tu.NoErr(enc.NameFromStr(s)) }

	// Testbed root
	rootSigner := tu.NoErr(signer.KeygenEd25519(sec.MakeKeyName(n("/root"))))
	rootKeyData := tu.NoErr(signer.MarshalSecretToData(rootSigner))
	rootCertWire := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    rootSigner,
		Data:      rootKeyData,
		IssuerId:  enc.NewGenericComponent("self"),
		NotBefore: nb,
		NotAfter:  na,
	}))
	rootCertData, _, _ := spec.Spec{}.ReadData(enc.NewWireView(rootCertWire))

	// Owner <= testbed
	ownerSigner := tu.NoErr(signer.KeygenEd25519(sec.MakeKeyName(n("/root/owner"))))
	ownerKeyData := tu.NoErr(signer.MarshalSecretToData(ownerSigner))
	ownerCertWire := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    rootSigner,
		Data:      ownerKeyData,
		IssuerId:  enc.NewGenericComponent("root"),
		NotBefore: nb,
		NotAfter:  na,
	}))
	ownerCertData, _, _ := spec.Spec{}.ReadData(enc.NewWireView(ownerCertWire))

	// Workspace anchor (cert)
	anchorSigner := tu.NoErr(signer.KeygenEd25519(sec.MakeKeyName(n("/app"))))
	anchorKeyData := tu.NoErr(signer.MarshalSecretToData(anchorSigner))
	anchorCertWire := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    anchorSigner,
		Data:      anchorKeyData,
		IssuerId:  enc.NewGenericComponent("self"),
		NotBefore: nb,
		NotAfter:  na,
	}))
	anchorCertData, anchorSigCov, _ := spec.Spec{}.ReadData(enc.NewWireView(anchorCertWire))

	// Workspace preanchor (precert)
	preAnchorWire := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    ownerSigner,
		Data:      anchorKeyData,
		IssuerId:  enc.NewGenericComponent("owner"),
		NotBefore: nb,
		NotAfter:  na,
	}))
	preAnchorData, _, _ := spec.Spec{}.ReadData(enc.NewWireView(preAnchorWire))

	wrongPreAnchorWire := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    anchorSigner,
		Data:      anchorKeyData,
		IssuerId:  enc.NewGenericComponent("self"),
		NotBefore: nb,
		NotAfter:  na,
	}))
	wrongPreAnchorData, _, _ := spec.Spec{}.ReadData(enc.NewWireView(wrongPreAnchorWire))

	listContent := tu.NoErr(sec.EncodeCertList([]enc.Name{preAnchorData.Name()}))
	listPrefix := tu.NoErr(sec.CertListPrefix(anchorSigner.KeyName()))
	listName := listPrefix.Append(enc.NewVersionComponent(uint64(time.Now().UnixMicro())))
	listWireEnc := tu.NoErr(spec.Spec{}.MakeData(listName, &ndn.DataConfig{
		Freshness:    optional.Some(time.Minute),
		SigNotBefore: optional.Some(nb),
		SigNotAfter:  optional.Some(na),
	}, listContent, anchorSigner))
	listData, _, _ := spec.Spec{}.ReadData(enc.NewWireView(listWireEnc.Wire))

	invalidSignedList := tu.NoErr(spec.Spec{}.MakeData(listName, &ndn.DataConfig{
		Freshness:    optional.Some(time.Minute),
		SigNotBefore: optional.Some(nb),
		SigNotAfter:  optional.Some(na),
	}, listContent, rootSigner))

	wrongListContent := tu.NoErr(sec.EncodeCertList([]enc.Name{wrongPreAnchorData.Name()}))
	wrongListWire := tu.NoErr(spec.Spec{}.MakeData(listName, &ndn.DataConfig{
		Freshness:    optional.Some(time.Minute),
		SigNotBefore: optional.Some(nb),
		SigNotAfter:  optional.Some(na),
	}, wrongListContent, anchorSigner))

	userSigner := tu.NoErr(signer.KeygenEd25519(sec.MakeKeyName(n("/app/user/alice"))))
	userKeyData := tu.NoErr(signer.MarshalSecretToData(userSigner))
	userCertWire := tu.NoErr(sec.SignCert(sec.SignCertArgs{
		Signer:    anchorSigner,
		Data:      userKeyData,
		IssuerId:  enc.NewGenericComponent("app"),
		NotBefore: nb,
		NotAfter:  na,
	}))
	userCertData, _, _ := spec.Spec{}.ReadData(enc.NewWireView(userCertWire))

	payload := enc.Wire{[]byte{0x01}}
	dataWire := tu.NoErr(spec.Spec{}.MakeData(n("/app/user/alice/data"), &ndn.DataConfig{
		Freshness: optional.Some(time.Minute),
	}, payload, userSigner))
	dataPkt, dataSigCov, _ := spec.Spec{}.ReadData(enc.NewWireView(dataWire.Wire))

	require.True(t, schema.Check(anchorCertData.Name(), anchorCertData.Name()))
	require.True(t, schema.Check(preAnchorData.Name(), ownerCertData.Name()))
	require.True(t, schema.Check(listData.Name(), anchorCertData.Name()))
	require.True(t, schema.Check(userCertData.Name(), anchorCertData.Name()))
	require.True(t, schema.Check(dataPkt.Name(), userCertData.Name()))

	network[anchorCertData.Name().String()] = anchorCertWire
	network[userCertData.Name().String()] = userCertWire
	network[ownerCertData.Name().String()] = ownerCertWire

	type stage struct {
		name          string
		add           map[string]enc.Wire
		expectAnchor  bool
		expectData    bool
		expectErrPart string
	}

	stages := []stage{
		{
			name:          "no certlist",
			add:           map[string]enc.Wire{},
			expectErrPart: "CertList",
		},
		{
			name: "certlist wrong signer",
			add: map[string]enc.Wire{
				listName.String(): invalidSignedList.Wire,
			},
			expectErrPart: "certlist invalid",
		},
		{
			name: "certlist wrong target",
			add: map[string]enc.Wire{
				listName.String():                  wrongListWire.Wire,
				wrongPreAnchorData.Name().String(): wrongPreAnchorWire,
			},
			expectErrPart: "no chain",
		},
		{
			name: "certlist ok",
			add: map[string]enc.Wire{
				listData.Name().String():      listWireEnc.Wire,
				preAnchorData.Name().String(): preAnchorWire,
			},
			expectAnchor: true,
			expectData:   true,
		},
	}

	validateOnce := func(trust *sec.TrustConfig, data ndn.Data, sigCov enc.Wire) (bool, error) {
		tcTestFetchCount = 0
		done := make(chan struct {
			v   bool
			err error
		}, 1)
		trust.Validate(sec.TrustConfigValidateArgs{
			Data:       data,
			DataSigCov: sigCov,
			Fetch:      fetchFun,
			Callback: func(valid bool, err error) {
				done <- struct {
					v   bool
					err error
				}{v: valid, err: err}
			},
		})
		res := <-done
		return res.v, res.err
	}

	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			tcTestKeyChain = keychain.NewKeyChainMem(store)
			kc := tcTestKeyChain

			for k, v := range st.add {
				network[k] = v
			}
			require.NoError(t, kc.InsertCert(rootCertWire.Join()))
			trust, err := sec.NewTrustConfig(kc, schema, []enc.Name{rootCertData.Name()})
			require.NoError(t, err)

			// Validate anchor cert first, then user data.
			anchorValid, anchorErr := validateOnce(trust, anchorCertData, anchorSigCov)
			dataValid, dataErr := validateOnce(trust, dataPkt, dataSigCov)
			if st.expectData {
				require.True(t, dataValid)
				require.NoError(t, dataErr)
			} else {
				require.False(t, dataValid)
				require.Error(t, dataErr)
				if st.expectErrPart != "" {
					require.Contains(t, dataErr.Error(), st.expectErrPart)
				}
			}

			if st.expectAnchor {
				require.True(t, anchorValid)
				require.NoError(t, anchorErr)
			} else {
				require.False(t, anchorValid)
				require.Error(t, anchorErr)
				if st.expectErrPart != "" {
					require.Contains(t, anchorErr.Error(), st.expectErrPart)
				}
			}
		})
	}
}

// (AI GENERATED DESCRIPTION): Initializes an in‑memory store and key chain, loads an LVS trust schema, and runs trust configuration tests.
func TestTrustConfigLvsIntra(t *testing.T) {
	tu.SetT(t)

	store := storage.NewMemoryStore()
	tcTestKeyChain = keychain.NewKeyChainMem(store)
	schemaIntra, err := trust_schema.NewLvsSchema(TRUST_CONFIG_INTRA_LVS)
	require.NoError(t, err)

	testTrustConfigIntra(t, schemaIntra)
}

func TestTrustConfigLvsInter(t *testing.T) {
	tu.SetT(t)

	store := storage.NewMemoryStore()
	tcTestKeyChain = keychain.NewKeyChainMem(store)
	schemaInter, err := trust_schema.NewLvsSchema(TRUST_CONFIG_INTER_LVS)
	require.NoError(t, err)

	testTrustConfigInter(t, schemaInter)
}
