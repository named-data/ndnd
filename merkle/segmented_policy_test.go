package merkle

import (
	"bytes"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/merklelog"
	"github.com/named-data/ndnd/std/ndn"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
	"github.com/named-data/ndnd/std/object"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/stretchr/testify/require"
)

func TestExpiredCertificateMerkleSegmentedConsume(t *testing.T) {
	f := newE2EFixture(t)
	now := time.Now()
	key, err := signer.KeygenEd25519(sec.MakeKeyName(e2eName(t, "/app/segmented")))
	require.NoError(t, err)
	secret, err := signer.MarshalSecretToData(key)
	require.NoError(t, err)
	cert, err := sec.SignCert(sec.SignCertArgs{
		Signer: f.rootSigner, Data: secret, IssuerId: enc.NewGenericComponent("root"),
		NotBefore: now.Add(-45 * time.Minute), NotAfter: now.Add(-15 * time.Minute),
	})
	require.NoError(t, err)
	require.NoError(t, f.consumerKeyChain.InsertCert(cert.Join()))
	name := e2eName(t, "/app/segmented/v=1")
	content := bytes.Repeat([]byte("segment"), 3000)
	_, err = object.Produce(ndn.ProduceArgs{Name: name, Content: enc.Wire{content}}, f.serverStore, signer.AsContextSigner(key))
	require.NoError(t, err)
	hashes := [][]byte{e2eDataHash(cert)}
	for segment := uint64(0); segment < 3; segment++ {
		raw, err := f.serverStore.Get(name.Append(enc.NewSegmentComponent(segment)), false)
		require.NoError(t, err)
		require.NotEmpty(t, raw)
		hashes = append(hashes, e2eDataHash(enc.Wire{raw}))
	}
	entry, err := merklelog.EncodeLogEntry(&defn.LogEntry{
		IngestTime: time.Duration(now.Add(-30*time.Minute).UnixMilli()) * time.Millisecond, DataHashes: hashes,
	})
	require.NoError(t, err)
	_, err = f.service.tree.Append(entry)
	require.NoError(t, err)
	require.NoError(t, f.service.engine.AttachHandler(name, func(args ndn.InterestHandlerArgs) {
		raw, err := f.serverStore.Get(args.Interest.Name(), false)
		if err == nil && len(raw) != 0 {
			_ = args.Reply(enc.Wire{raw})
		}
	}))
	t.Cleanup(func() { require.NoError(t, f.service.engine.DetachHandler(name)) })
	completed := make(chan ndn.ConsumeState, 1)
	f.consumerClient.ConsumeExt(ndn.ConsumeExtArgs{
		Name: name, OnCertExpired: merklelog.NewCertExpiredPolicy(f.logClient),
		Callback: func(state ndn.ConsumeState) { completed <- state },
	})
	select {
	case state := <-completed:
		require.NoError(t, state.Error())
		require.Equal(t, content, state.Content().Join())
	case <-time.After(e2eOperationTimeout):
		t.Fatal("segmented fetch stalled after asynchronous Merkle validation")
	}
}
