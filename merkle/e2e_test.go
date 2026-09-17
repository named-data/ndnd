package merkle

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/merklelog"
	"github.com/named-data/ndnd/std/ndn"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/stretchr/testify/require"
)

const e2eOperationTimeout = 5 * time.Second

func TestExpiredCertificateMerkleLogEndToEnd(t *testing.T) {
	fixture := newE2EFixture(t)
	validFrom := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	validUntil := time.Now().Add(3 * time.Second).Truncate(time.Millisecond)

	accepted := fixture.newEvidence(t, "/app/accepted", validFrom, validUntil)
	missingData := fixture.newEvidence(t, "/app/missing-data", validFrom, validUntil)
	missingCert := fixture.newEvidence(t, "/app/missing-cert", validFrom, validUntil)
	outsideValidity := fixture.newEvidence(
		t,
		"/app/outside-validity",
		time.Now().Add(-2*time.Hour),
		time.Now().Add(-time.Hour),
	)
	loggedHashes := [][]byte{
		accepted.dataHash,
		accepted.certHash,
		missingData.certHash,
		missingCert.dataHash,
		outsideValidity.dataHash,
		outsideValidity.certHash,
	}

	appendResponse, err := fixture.append(loggedHashes)
	require.NoError(t, err)
	require.Len(t, appendResponse.Results, len(loggedHashes))
	for i, result := range appendResponse.Results {
		require.Equal(t, defn.AppendStatusOK, result.Status, "append result %d", i)
		require.True(t, result.LeafIndex.IsSet(), "append result %d has no leaf index", i)
		require.Equal(t, uint64(0), result.LeafIndex.Unwrap(), "append result %d", i)
	}
	require.Equal(t, uint64(1), fixture.service.tree.Size())

	// Repeating an authenticated append must preserve the original evidence.
	duplicateResponse, err := fixture.append([][]byte{accepted.dataHash, accepted.certHash})
	require.NoError(t, err)
	for i, result := range duplicateResponse.Results {
		require.Equal(t, defn.AppendStatusDuplicate, result.Status, "duplicate result %d", i)
		require.Equal(t, uint64(0), result.LeafIndex.Unwrap(), "duplicate result %d", i)
	}
	require.Equal(t, uint64(1), fixture.service.tree.Size())

	// Loading a second Tree from the durable store must reconstruct the same
	// root and make every committed hash independently provable.
	restored, err := merklelog.OpenTree(fixture.logStore)
	require.NoError(t, err)
	require.Equal(t, fixture.service.tree.Size(), restored.Size())
	require.True(t, bytes.Equal(fixture.service.tree.Root().RootHash, restored.Root().RootHash))
	for _, dataHash := range loggedHashes {
		leafIndex, ok := restored.Lookup(dataHash)
		require.True(t, ok, "restored tree is missing %x", dataHash)
		proof, err := restored.InclusionProof(leafIndex)
		require.NoError(t, err)
		require.NoError(t, merklelog.VerifyInclusion(dataHash, proof, restored.Root()))
	}

	ingestTime, ok := fixture.service.tree.LastIngestTime()
	require.True(t, ok)
	loggedAt := time.Unix(0, int64(ingestTime))
	require.False(t, loggedAt.Before(validFrom))
	require.False(t, loggedAt.After(validUntil))
	if wait := time.Until(validUntil) + time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	for _, evidence := range []*e2eEvidence{accepted, missingData, missingCert, outsideValidity} {
		require.True(t, sec.CertIsExpired(evidence.cert))
	}

	t.Run("accepts two proven relations", func(t *testing.T) {
		require.NoError(t, fixture.validate(accepted, merklelog.NewCertExpiredPolicy(fixture.logClient)))

		// Recursive validation must retrieve evidence for both relations:
		// Data <- expired child certificate and child certificate <- root.
		for _, dataHash := range [][]byte{accepted.dataHash, accepted.certHash} {
			checkName := merklelog.CheckPrefix(fixture.logPrefix).
				Append(enc.NewGenericBytesComponent(dataHash))
			wire, err := fixture.serverStore.Get(checkName, true)
			require.NoError(t, err)
			require.NotEmpty(t, wire, "validation did not retrieve proof for %x", dataHash)
		}
	})

	t.Run("rejects expired chain without policy", func(t *testing.T) {
		err := fixture.validate(accepted, nil)
		require.ErrorContains(t, err, "certificate is expired")
	})

	t.Run("rejects unlogged data", func(t *testing.T) {
		err := fixture.validate(missingData, merklelog.NewCertExpiredPolicy(fixture.logClient))
		require.ErrorContains(t, err, "not present in the Merkle log")
	})

	t.Run("rejects unlogged certificate", func(t *testing.T) {
		err := fixture.validate(missingCert, merklelog.NewCertExpiredPolicy(fixture.logClient))
		require.ErrorContains(t, err, "not present in the Merkle log")
	})

	t.Run("rejects evidence logged outside validity", func(t *testing.T) {
		err := fixture.validate(outsideValidity, merklelog.NewCertExpiredPolicy(fixture.logClient))
		require.ErrorContains(t, err, "logged outside certificate validity")
	})

	t.Run("rejects different raw packet wire", func(t *testing.T) {
		altered := *accepted
		altered.rawData = enc.Wire{bytes.Clone(accepted.rawData.Join())}
		altered.rawData[0][len(altered.rawData[0])-1] ^= 0xff
		err := fixture.validate(&altered, merklelog.NewCertExpiredPolicy(fixture.logClient))
		require.ErrorContains(t, err, "not present in the Merkle log")
	})

	t.Run("proof does not bypass signature validation", func(t *testing.T) {
		altered := *accepted
		altered.sigCovered = enc.Wire{[]byte("invalid signature input")}
		err := fixture.validate(&altered, merklelog.NewCertExpiredPolicy(fixture.logClient))
		require.ErrorContains(t, err, "signature is invalid")
	})

	t.Run("check returns included and not-found results", func(t *testing.T) {
		included, err := fixture.check(accepted.dataHash)
		require.NoError(t, err)
		require.Equal(t, defn.CheckStatusIncluded, included.Result.Status)
		require.NoError(t, merklelog.VerifyInclusion(
			accepted.dataHash,
			included.Result.Proof,
			included.Root,
		))

		missingHash := sha256.Sum256([]byte("not logged"))
		notFound, err := fixture.check(missingHash[:])
		require.NoError(t, err)
		require.Equal(t, defn.CheckStatusNotFound, notFound.Result.Status)
		require.Nil(t, notFound.Result.Proof)
	})

	t.Run("rejects tampered check response", func(t *testing.T) {
		dataHash := sha256.Sum256([]byte("tampered check response"))
		response, err := fixture.check(dataHash[:])
		require.NoError(t, err)
		require.Equal(t, defn.CheckStatusNotFound, response.Result.Status)

		segmentName := merklelog.CheckPrefix(fixture.logPrefix).
			Append(enc.NewGenericBytesComponent(dataHash[:])).
			Append(enc.NewVersionComponent(response.Root.TreeSize)).
			Append(enc.NewSegmentComponent(0))
		wire, err := fixture.serverStore.Get(segmentName, false)
		require.NoError(t, err)
		require.NotEmpty(t, wire)
		wire[len(wire)-1] ^= 0xff
		require.NoError(t, fixture.serverStore.Put(segmentName, wire))

		_, err = fixture.check(dataHash[:])
		require.Error(t, err)
	})
}

type e2eFixture struct {
	logPrefix        enc.Name
	service          *Log
	serverStore      *storage.BadgerStore
	logStore         *merklelog.BadgerStore
	consumerClient   ndn.Client
	consumerKeyChain ndn.KeyChain
	logClient        *merklelog.Client
	rootSigner       ndn.Signer
}

type e2eEvidence struct {
	data       ndn.Data
	rawData    enc.Wire
	sigCovered enc.Wire
	cert       ndn.Data
	dataHash   []byte
	certHash   []byte
}

func newE2EFixture(t *testing.T) *e2eFixture {
	t.Helper()
	logPrefix := e2eName(t, "/operator/merkle")
	serverFace, consumerFace := newE2EFacePair()
	serverEngine := basic.NewEngine(serverFace, basic.NewTimer())
	consumerEngine := basic.NewEngine(consumerFace, basic.NewTimer())

	serverStore, err := storage.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, serverStore.Close()) })
	logStore, err := merklelog.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logStore.Close()) })
	tree, err := merklelog.OpenTree(logStore)
	require.NoError(t, err)

	require.NoError(t, serverEngine.Start())
	t.Cleanup(func() {
		if serverEngine.IsRunning() {
			require.NoError(t, serverEngine.Stop())
		}
		if consumerEngine.IsRunning() {
			require.NoError(t, consumerEngine.Stop())
		}
		require.Eventually(t, func() bool {
			return !serverEngine.IsRunning() && !consumerEngine.IsRunning()
		}, time.Second, time.Millisecond)
	})
	require.NoError(t, consumerEngine.Start())

	now := time.Now()
	rootSigner, err := signer.KeygenEd25519(sec.MakeKeyName(e2eName(t, "/root")))
	require.NoError(t, err)
	rootWire, rootCert := e2eSelfSign(t, rootSigner, now.Add(-time.Hour), now.Add(time.Hour))
	logSigner, err := signer.KeygenEd25519(sec.MakeKeyName(e2eName(t, "/operator/logger")))
	require.NoError(t, err)
	logWire, logCert := e2eSelfSign(t, logSigner, now.Add(-time.Hour), now.Add(time.Hour))

	serverKeyChain := keychain.NewKeyChainMem(serverStore)
	require.NoError(t, serverKeyChain.InsertCert(rootWire.Join()))
	require.NoError(t, serverKeyChain.InsertKey(logSigner))
	serverTrust, err := sec.NewTrustConfig(
		serverKeyChain,
		e2eTrustSchema{signer: logSigner},
		[]enc.Name{rootCert.Name()},
	)
	require.NoError(t, err)
	serverClient := object.NewClient(serverEngine, serverStore, serverTrust)
	require.NoError(t, serverClient.Start())
	t.Cleanup(func() { require.NoError(t, serverClient.Stop()) })

	consumerStore := storage.NewMemoryStore()
	consumerKeyChain := keychain.NewKeyChainMem(consumerStore)
	require.NoError(t, consumerKeyChain.InsertKey(rootSigner))
	require.NoError(t, consumerKeyChain.InsertCert(rootWire.Join()))
	require.NoError(t, consumerKeyChain.InsertCert(logWire.Join()))
	consumerTrust, err := sec.NewTrustConfig(
		consumerKeyChain,
		e2eTrustSchema{signer: rootSigner},
		[]enc.Name{rootCert.Name(), logCert.Name()},
	)
	require.NoError(t, err)
	consumerClient := object.NewClient(consumerEngine, consumerStore, consumerTrust)
	require.NoError(t, consumerClient.Start())
	t.Cleanup(func() { require.NoError(t, consumerClient.Stop()) })

	service := NewLog(&Config{nameN: logPrefix})
	service.engine = serverEngine
	service.client = serverClient
	service.packetStore = serverStore
	service.logStore = logStore
	service.tree = tree
	require.NoError(t, serverClient.AttachCommandHandler(merklelog.AppendPrefix(logPrefix), service.onAppend))
	t.Cleanup(func() {
		require.NoError(t, serverClient.DetachCommandHandler(merklelog.AppendPrefix(logPrefix)))
	})
	require.NoError(t, serverEngine.AttachHandler(merklelog.CheckPrefix(logPrefix), service.onCheck))
	t.Cleanup(func() {
		require.NoError(t, serverEngine.DetachHandler(merklelog.CheckPrefix(logPrefix)))
	})

	logClient, err := merklelog.NewClient(consumerClient, logPrefix, rootSigner.KeyName())
	require.NoError(t, err)
	return &e2eFixture{
		logPrefix:        logPrefix,
		service:          service,
		serverStore:      serverStore,
		logStore:         logStore,
		consumerClient:   consumerClient,
		consumerKeyChain: consumerKeyChain,
		logClient:        logClient,
		rootSigner:       rootSigner,
	}
}

func (f *e2eFixture) newEvidence(
	t *testing.T,
	identity string,
	validFrom time.Time,
	validUntil time.Time,
) *e2eEvidence {
	t.Helper()
	childSigner, err := signer.KeygenEd25519(sec.MakeKeyName(e2eName(t, identity)))
	require.NoError(t, err)
	childKey, err := signer.MarshalSecretToData(childSigner)
	require.NoError(t, err)
	childWire, err := sec.SignCert(sec.SignCertArgs{
		Signer:    f.rootSigner,
		Data:      childKey,
		IssuerId:  enc.NewGenericComponent("root"),
		NotBefore: validFrom,
		NotAfter:  validUntil,
	})
	require.NoError(t, err)
	childCert, _, err := spec.Spec{}.ReadData(enc.NewWireView(childWire))
	require.NoError(t, err)
	require.NoError(t, f.consumerKeyChain.InsertCert(childWire.Join()))

	dataWire, err := spec.Spec{}.MakeData(
		e2eName(t, identity+"/data"),
		&ndn.DataConfig{},
		enc.Wire{[]byte(identity)},
		signer.AsContextSigner(childSigner),
	)
	require.NoError(t, err)
	data, dataSigCovered, err := spec.Spec{}.ReadData(enc.NewWireView(dataWire.Wire))
	require.NoError(t, err)
	return &e2eEvidence{
		data:       data,
		rawData:    dataWire.Wire,
		sigCovered: dataSigCovered,
		cert:       childCert,
		dataHash:   e2eDataHash(dataWire.Wire),
		certHash:   e2eDataHash(childWire),
	}
}

func (f *e2eFixture) append(dataHashes [][]byte) (*defn.AppendResponse, error) {
	type result struct {
		response *defn.AppendResponse
		err      error
	}
	completed := make(chan result, 1)
	f.logClient.Append(dataHashes, func(response *defn.AppendResponse, err error) {
		completed <- result{response: response, err: err}
	})
	select {
	case ret := <-completed:
		return ret.response, ret.err
	case <-time.After(e2eOperationTimeout):
		return nil, fmt.Errorf("append timed out")
	}
}

func (f *e2eFixture) check(dataHash []byte) (*defn.CheckResponse, error) {
	type result struct {
		response *defn.CheckResponse
		err      error
	}
	completed := make(chan result, 1)
	f.logClient.Check(dataHash, func(response *defn.CheckResponse, err error) {
		completed <- result{response: response, err: err}
	})
	select {
	case ret := <-completed:
		return ret.response, ret.err
	case <-time.After(e2eOperationTimeout):
		return nil, fmt.Errorf("check timed out")
	}
}

func (f *e2eFixture) validate(
	evidence *e2eEvidence,
	policy ndn.CertExpiredCallback,
) error {
	completed := make(chan error, 1)
	f.consumerClient.ValidateExt(ndn.ValidateExtArgs{
		Data:          evidence.data,
		RawData:       evidence.rawData,
		SigCovered:    evidence.sigCovered,
		OnCertExpired: policy,
		Callback: func(valid bool, err error) {
			if !valid && err == nil {
				err = fmt.Errorf("validation failed")
			}
			completed <- err
		},
	})
	select {
	case err := <-completed:
		return err
	case <-time.After(e2eOperationTimeout):
		return fmt.Errorf("validation timed out")
	}
}

func e2eDataHash(wire enc.Wire) []byte {
	hash := sha256.Sum256(wire.Join())
	return hash[:]
}

func e2eSelfSign(
	t *testing.T,
	packetSigner ndn.Signer,
	notBefore time.Time,
	notAfter time.Time,
) (enc.Wire, ndn.Data) {
	t.Helper()
	wire, err := sec.SelfSign(sec.SignCertArgs{
		Signer:    packetSigner,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
	require.NoError(t, err)
	cert, _, err := spec.Spec{}.ReadData(enc.NewWireView(wire))
	require.NoError(t, err)
	return wire, cert
}

func e2eName(t *testing.T, value string) enc.Name {
	t.Helper()
	name, err := enc.NameFromStr(value)
	require.NoError(t, err)
	return name
}

type e2eTrustSchema struct {
	signer ndn.Signer
}

func (e2eTrustSchema) Check(enc.Name, enc.Name) bool { return true }

func (s e2eTrustSchema) Suggest(enc.Name, ndn.KeyChain) ndn.Signer {
	return s.signer
}

type e2eFace struct {
	running  atomic.Bool
	peer     *e2eFace
	mutex    sync.RWMutex
	onPacket func([]byte)
}

func newE2EFacePair() (*e2eFace, *e2eFace) {
	left := &e2eFace{}
	right := &e2eFace{}
	left.peer = right
	right.peer = left
	return left, right
}

func (*e2eFace) String() string { return "e2e-face" }

func (f *e2eFace) IsRunning() bool { return f.running.Load() }

func (*e2eFace) IsLocal() bool { return true }

func (f *e2eFace) OnPacket(onPacket func([]byte)) {
	f.mutex.Lock()
	f.onPacket = onPacket
	f.mutex.Unlock()
}

func (*e2eFace) OnError(func(error)) {}

func (f *e2eFace) Open() error {
	if !f.running.CompareAndSwap(false, true) {
		return fmt.Errorf("face is already running")
	}
	return nil
}

func (f *e2eFace) Close() error {
	if !f.running.CompareAndSwap(true, false) {
		return fmt.Errorf("face is not running")
	}
	return nil
}

func (f *e2eFace) Send(wire enc.Wire) error {
	if !f.running.Load() || !f.peer.running.Load() {
		return fmt.Errorf("face is not running")
	}
	f.peer.mutex.RLock()
	onPacket := f.peer.onPacket
	f.peer.mutex.RUnlock()
	if onPacket == nil {
		return fmt.Errorf("peer has no packet handler")
	}
	onPacket(bytes.Clone(wire.Join()))
	return nil
}

func (*e2eFace) OnUp(func()) func() { return func() {} }

func (*e2eFace) OnDown(func()) func() { return func() {} }
