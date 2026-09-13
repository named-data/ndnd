package merklelog

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/require"
)

func TestCertExpiredPolicyAcceptsIngestTimeWithinValidity(t *testing.T) {
	rawData := enc.Wire{[]byte("exact Data wire")}
	validFrom := time.UnixMilli(1_700_000_000_000)
	validUntil := validFrom.Add(time.Hour)
	cert := policyTestCert(t, validFrom, validUntil)

	for _, ingestTime := range []time.Time{
		validFrom,
		validFrom.Add(30 * time.Minute),
		validUntil,
	} {
		t.Run(ingestTime.String(), func(t *testing.T) {
			client := policyTestClient(t, rawData, ingestTime)
			err := runPolicy(NewCertExpiredPolicy(client), ndn.CertExpiredCallbackArgs{
				Data:    cert,
				RawData: rawData,
				Cert:    cert,
			})
			require.NoError(t, err)
		})
	}
}

func TestCertExpiredPolicyRejectsInvalidEvidence(t *testing.T) {
	rawData := enc.Wire{[]byte("exact Data wire")}
	validFrom := time.UnixMilli(1_700_000_000_000)
	validUntil := validFrom.Add(time.Hour)
	cert := policyTestCert(t, validFrom, validUntil)
	args := ndn.CertExpiredCallbackArgs{Data: cert, RawData: rawData, Cert: cert}

	t.Run("outside validity", func(t *testing.T) {
		client := policyTestClient(t, rawData, validUntil.Add(time.Millisecond))
		require.ErrorContains(t, runPolicy(NewCertExpiredPolicy(client), args), "outside certificate validity")
	})

	t.Run("not found", func(t *testing.T) {
		dataHash := sha256.Sum256(rawData.Join())
		emptyTree := NewTree()
		mock := &commandClientMock{response: (&defn.CheckResponse{
			Root: emptyTree.Root(),
			Result: &defn.CheckResult{
				DataHash: dataHash[:],
				Status:   defn.CheckStatusNotFound,
			},
		}).Encode()}
		client, err := NewClient(mock, clientTestName(t, "/operator/merkle"), clientTestName(t, "/requester"))
		require.NoError(t, err)
		require.ErrorContains(t, runPolicy(NewCertExpiredPolicy(client), args), "not present")
	})

	t.Run("different wire", func(t *testing.T) {
		client := policyTestClient(t, rawData, validFrom)
		mismatchedArgs := args
		mismatchedArgs.RawData = enc.Wire{[]byte("different Data wire")}
		require.ErrorContains(t, runPolicy(NewCertExpiredPolicy(client), mismatchedArgs), "does not match requested Data hash")
	})

	t.Run("check error", func(t *testing.T) {
		client, err := NewClient(
			&commandClientMock{err: errors.New("timeout")},
			clientTestName(t, "/operator/merkle"),
			clientTestName(t, "/requester"),
		)
		require.NoError(t, err)
		require.ErrorContains(t, runPolicy(NewCertExpiredPolicy(client), args), "timeout")
	})
}

func TestCertExpiredPolicyRejectsMissingInputs(t *testing.T) {
	validFrom := time.UnixMilli(1_700_000_000_000)
	cert := policyTestCert(t, validFrom, validFrom.Add(time.Hour))
	client := policyTestClient(t, enc.Wire{[]byte("wire")}, validFrom)
	policy := NewCertExpiredPolicy(client)

	require.ErrorContains(t, runPolicy(policy, ndn.CertExpiredCallbackArgs{}), "Data packet is nil")
	require.ErrorContains(t, runPolicy(policy, ndn.CertExpiredCallbackArgs{
		Data: cert,
		Cert: cert,
	}), "wire is unavailable")

	noValidityWire, err := spec.Spec{}.MakeData(
		clientTestName(t, "/certificate"),
		&ndn.DataConfig{},
		nil,
		signer.NewSha256Signer(),
	)
	require.NoError(t, err)
	noValidity, _, err := spec.Spec{}.ReadData(enc.NewWireView(noValidityWire.Wire))
	require.NoError(t, err)
	require.ErrorContains(t, runPolicy(policy, ndn.CertExpiredCallbackArgs{
		Data:    cert,
		RawData: enc.Wire{[]byte("wire")},
		Cert:    noValidity,
	}), "invalid validity period")

	require.ErrorContains(t, runPolicy(NewCertExpiredPolicy(nil), ndn.CertExpiredCallbackArgs{}), "client is nil")
}

func TestCertExpiredPolicyValidatesDataAndCertificateSeparately(t *testing.T) {
	now := time.Now()
	rootSigner, err := signer.KeygenEd25519(sec.MakeKeyName(clientTestName(t, "/root")))
	require.NoError(t, err)
	rootWire, err := sec.SelfSign(sec.SignCertArgs{
		Signer:    rootSigner,
		NotBefore: now.Add(-3 * time.Hour),
		NotAfter:  now.Add(time.Hour),
	})
	require.NoError(t, err)
	rootCert, _, err := spec.Spec{}.ReadData(enc.NewWireView(rootWire))
	require.NoError(t, err)

	childSigner, err := signer.KeygenEd25519(sec.MakeKeyName(clientTestName(t, "/app")))
	require.NoError(t, err)
	childKey, err := signer.MarshalSecretToData(childSigner)
	require.NoError(t, err)
	childWire, err := sec.SignCert(sec.SignCertArgs{
		Signer:    rootSigner,
		Data:      childKey,
		IssuerId:  enc.NewGenericComponent("root"),
		NotBefore: now.Add(-2 * time.Hour),
		NotAfter:  now.Add(-time.Hour),
	})
	require.NoError(t, err)
	childCert, childSigCovered, err := spec.Spec{}.ReadData(enc.NewWireView(childWire))
	require.NoError(t, err)

	dataWire, err := spec.Spec{}.MakeData(
		clientTestName(t, "/app/data"),
		&ndn.DataConfig{},
		enc.Wire{[]byte("payload")},
		signer.AsContextSigner(childSigner),
	)
	require.NoError(t, err)
	data, dataSigCovered, err := spec.Spec{}.ReadData(enc.NewWireView(dataWire.Wire))
	require.NoError(t, err)

	dataHash := sha256.Sum256(dataWire.Wire.Join())
	childHash := sha256.Sum256(childWire.Join())
	tree := NewTree()
	entryWire, err := EncodeLogEntry(&defn.LogEntry{
		IngestTime: time.Duration(now.Add(-90*time.Minute).UnixMilli()) * time.Millisecond,
		DataHashes: [][]byte{dataHash[:], childHash[:]},
	})
	require.NoError(t, err)
	_, err = tree.Append(entryWire)
	require.NoError(t, err)

	logTransport := &proofCommandClient{tree: tree}
	logClient, err := NewClient(
		logTransport,
		clientTestName(t, "/operator/merkle"),
		clientTestName(t, "/requester"),
	)
	require.NoError(t, err)

	keychainStore := storage.NewMemoryStore()
	keyChain := keychain.NewKeyChainMem(keychainStore)
	require.NoError(t, keyChain.InsertCert(rootWire.Join()))
	trust, err := sec.NewTrustConfig(keyChain, allowAllTrustSchema{}, []enc.Name{rootCert.Name()})
	require.NoError(t, err)

	validate := func(sigCovered enc.Wire) error {
		result := make(chan error, 1)
		trust.Validate(sec.TrustConfigValidateArgs{
			Data:       data,
			RawData:    dataWire.Wire,
			DataSigCov: sigCovered,
			Fetch: func(name enc.Name, _ *ndn.InterestConfig, callback ndn.ExpressCallbackFunc) {
				if name.IsPrefix(childCert.Name()) {
					callback(ndn.ExpressCallbackArgs{
						Result:     ndn.InterestResultData,
						Data:       childCert,
						RawData:    childWire,
						SigCovered: childSigCovered,
					})
					return
				}
				callback(ndn.ExpressCallbackArgs{Error: fmt.Errorf("certificate not found: %s", name)})
			},
			Callback: func(valid bool, err error) {
				if !valid && err == nil {
					err = errors.New("validation failed")
				}
				result <- err
			},
			OnCertExpired: NewCertExpiredPolicy(logClient),
		})
		return <-result
	}

	require.ErrorContains(t, validate(enc.Wire{[]byte("invalid signature input")}), "signature is invalid")
	require.Equal(t, [][]byte{dataHash[:]}, logTransport.queries)
	require.NoError(t, validate(dataSigCovered))
	require.Equal(t, [][]byte{dataHash[:], dataHash[:], childHash[:]}, logTransport.queries)
}

func policyTestClient(t *testing.T, rawData enc.Wire, ingestTime time.Time) *Client {
	t.Helper()
	dataHash := sha256.Sum256(rawData.Join())
	tree := NewTree()
	entryWire, err := EncodeLogEntry(&defn.LogEntry{
		IngestTime: time.Duration(ingestTime.UnixMilli()) * time.Millisecond,
		DataHashes: [][]byte{dataHash[:]},
	})
	require.NoError(t, err)
	_, err = tree.Append(entryWire)
	require.NoError(t, err)
	proof, err := tree.InclusionProof(0)
	require.NoError(t, err)

	mock := &commandClientMock{response: (&defn.CheckResponse{
		Root: tree.Root(),
		Result: &defn.CheckResult{
			DataHash: dataHash[:],
			Status:   defn.CheckStatusIncluded,
			Proof:    proof,
		},
	}).Encode(), responseVersion: tree.Size()}
	client, err := NewClient(mock, clientTestName(t, "/operator/merkle"), clientTestName(t, "/requester"))
	require.NoError(t, err)
	return client
}

func policyTestCert(t *testing.T, validFrom, validUntil time.Time) ndn.Data {
	t.Helper()
	wire, err := spec.Spec{}.MakeData(
		clientTestName(t, "/certificate"),
		&ndn.DataConfig{
			SigNotBefore: optional.Some(validFrom),
			SigNotAfter:  optional.Some(validUntil),
		},
		nil,
		signer.NewSha256Signer(),
	)
	require.NoError(t, err)
	cert, _, err := spec.Spec{}.ReadData(enc.NewWireView(wire.Wire))
	require.NoError(t, err)
	return cert
}

func runPolicy(policy ndn.CertExpiredCallback, args ndn.CertExpiredCallbackArgs) error {
	result := make(chan error, 1)
	policy(args, func(err error) { result <- err })
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		return errors.New("policy did not complete")
	}
}

type allowAllTrustSchema struct{}

func (allowAllTrustSchema) Check(enc.Name, enc.Name) bool             { return true }
func (allowAllTrustSchema) Suggest(enc.Name, ndn.KeyChain) ndn.Signer { return nil }

type proofCommandClient struct {
	ndn.Client
	tree    *Tree
	queries [][]byte
}

func (c *proofCommandClient) ConsumeExt(args ndn.ConsumeExtArgs) {
	dataHash := args.Name.At(-1).Val
	response := &defn.CheckResponse{
		Root: c.tree.Root(),
		Result: &defn.CheckResult{
			DataHash: bytes.Clone(dataHash),
			Status:   defn.CheckStatusNotFound,
		},
	}
	c.queries = append(c.queries, bytes.Clone(dataHash))
	if leafIndex, ok := c.tree.Lookup(dataHash); ok {
		response.Result.Status = defn.CheckStatusIncluded
		proof, err := c.tree.InclusionProof(leafIndex)
		if err != nil {
			args.Callback(&consumeStateMock{err: err})
			return
		}
		response.Result.Proof = proof
	}
	args.Callback(&consumeStateMock{
		name:    args.Name.Append(enc.NewVersionComponent(c.tree.Size())),
		content: response.Encode(),
	})
}
