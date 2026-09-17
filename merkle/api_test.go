package merkle

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/merklelog"
	"github.com/named-data/ndnd/std/ndn"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/stretchr/testify/require"
)

func TestAppendAndCheck(t *testing.T) {
	m := newTestLog(t)
	hash0 := apiTestHash(0)
	hash1 := apiTestHash(1)

	response, err := m.append(&defn.AppendRequest{
		DataHashes: [][]byte{hash0, hash1, hash0, {0x01}},
	})
	require.NoError(t, err)
	require.Len(t, response.Results, 4)
	require.Equal(t, defn.AppendStatusOK, response.Results[0].Status)
	require.Equal(t, defn.AppendStatusOK, response.Results[1].Status)
	require.Equal(t, defn.AppendStatusDuplicate, response.Results[2].Status)
	require.Equal(t, defn.AppendStatusFailed, response.Results[3].Status)
	for _, i := range []int{0, 1, 2} {
		require.Equal(t, uint64(0), response.Results[i].LeafIndex.Unwrap())
	}
	require.False(t, response.Results[3].LeafIndex.IsSet())
	require.Equal(t, uint64(1), m.tree.Size())

	check, err := m.check(hash0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), check.Root.TreeSize)
	require.Equal(t, defn.CheckStatusIncluded, check.Result.Status)
	require.NoError(t, merklelog.VerifyInclusion(hash0, check.Result.Proof, check.Root))

	missing, err := m.check(apiTestHash(99))
	require.NoError(t, err)
	require.Equal(t, defn.CheckStatusNotFound, missing.Result.Status)
	require.Nil(t, missing.Result.Proof)

	second, err := m.check(hash1)
	require.NoError(t, err)
	require.Equal(t, defn.CheckStatusIncluded, second.Result.Status)
	require.NoError(t, merklelog.VerifyInclusion(hash1, second.Result.Proof, second.Root))
}

func TestAppendReplayAndMonotonicTime(t *testing.T) {
	m := newTestLog(t)
	firstNow := m.now()

	first, err := m.append(&defn.AppendRequest{DataHashes: [][]byte{apiTestHash(0)}})
	require.NoError(t, err)
	require.Equal(t, defn.AppendStatusOK, first.Results[0].Status)
	firstIngestTime, ok := m.tree.LastIngestTime()
	require.True(t, ok)
	require.Equal(t, time.Duration(firstNow.UnixMilli())*time.Millisecond, firstIngestTime)

	replay, err := m.append(&defn.AppendRequest{DataHashes: [][]byte{apiTestHash(0)}})
	require.NoError(t, err)
	require.Equal(t, defn.AppendStatusDuplicate, replay.Results[0].Status)
	require.Equal(t, uint64(1), m.tree.Size())

	m.now = func() time.Time { return firstNow.Add(-time.Hour) }
	second, err := m.append(&defn.AppendRequest{DataHashes: [][]byte{apiTestHash(1)}})
	require.NoError(t, err)
	require.Equal(t, defn.AppendStatusOK, second.Results[0].Status)
	secondIngestTime, ok := m.tree.LastIngestTime()
	require.True(t, ok)
	require.Equal(t, firstIngestTime+time.Millisecond, secondIngestTime)
}

func TestCheckHandlerServesObject(t *testing.T) {
	m := newTestLog(t)
	packetStore, err := storage.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, packetStore.Close()) })
	m.packetStore = packetStore
	m.client = &checkProducer{store: packetStore}

	hash := apiTestHash(0)
	_, err = m.append(&defn.AppendRequest{DataHashes: [][]byte{hash}})
	require.NoError(t, err)
	checkName := merklelog.CheckPrefix(m.config.nameN).
		Append(enc.NewGenericBytesComponent(hash))

	firstReply := make(chan enc.Wire, 1)
	m.onCheck(ndn.InterestHandlerArgs{
		Interest: makeCheckInterest(t, checkName, true),
		Reply: func(wire enc.Wire) error {
			firstReply <- wire
			return nil
		},
	})

	var firstWire enc.Wire
	select {
	case firstWire = <-firstReply:
	case <-time.After(time.Second):
		t.Fatal("check handler did not reply")
	}
	data, _, err := spec.Spec{}.ReadData(enc.NewWireView(firstWire))
	require.NoError(t, err)
	expectedName := checkName.
		Append(enc.NewVersionComponent(m.tree.Size())).
		Append(enc.NewSegmentComponent(0))
	require.True(t, expectedName.Equal(data.Name()))
	response, err := defn.ParseCheckResponse(enc.NewWireView(data.Content()), false)
	require.NoError(t, err)
	require.NoError(t, merklelog.VerifyInclusion(hash, response.Result.Proof, response.Root))

	segmentReply := make(chan enc.Wire, 1)
	m.onCheck(ndn.InterestHandlerArgs{
		Interest: makeCheckInterest(t, expectedName, false),
		Reply: func(wire enc.Wire) error {
			segmentReply <- wire
			return nil
		},
	})
	select {
	case segmentWire := <-segmentReply:
		require.Equal(t, firstWire.Join(), segmentWire.Join())
	case <-time.After(time.Second):
		t.Fatal("check handler did not serve the stored segment")
	}
}

func TestAppendStoreFailure(t *testing.T) {
	storeErr := errors.New("store failure")
	tree, err := merklelog.OpenTree(&failingAppendStore{
		Store: merklelog.NewMemoryStore(),
		err:   storeErr,
	})
	require.NoError(t, err)
	m := newTestLog(t)
	m.tree = tree

	response, err := m.append(&defn.AppendRequest{DataHashes: [][]byte{apiTestHash(0)}})
	require.ErrorIs(t, err, storeErr)
	require.Equal(t, defn.AppendStatusFailed, response.Results[0].Status)
	require.False(t, response.Results[0].LeafIndex.IsSet())
	require.Zero(t, tree.Size())
}

func TestRequestNameValidation(t *testing.T) {
	m := newTestLog(t)
	prefix := merklelog.AppendPrefix(m.config.nameN)
	nowMillis := uint64(m.now().UnixMilli())
	valid := prefix.Clone().
		Append(enc.NewGenericComponent("requester")).
		Append(enc.NewTimestampComponent(nowMillis))
	require.NoError(t, m.validateRequestName(valid, prefix))

	tests := map[string]enc.Name{
		"wrong command": merklelog.CheckPrefix(m.config.nameN).Clone().
			Append(enc.NewGenericComponent("requester")).
			Append(enc.NewTimestampComponent(nowMillis)),
		"no requester": prefix.Clone().Append(enc.NewTimestampComponent(nowMillis)),
		"no timestamp": prefix.Clone().
			Append(enc.NewGenericComponent("requester"), enc.NewGenericComponent("time")),
		"stale": prefix.Clone().
			Append(enc.NewGenericComponent("requester")).
			Append(enc.NewTimestampComponent(uint64(m.now().Add(-time.Minute - time.Millisecond).UnixMilli()))),
		"future": prefix.Clone().
			Append(enc.NewGenericComponent("requester")).
			Append(enc.NewTimestampComponent(uint64(m.now().Add(time.Minute + time.Millisecond).UnixMilli()))),
		"non-canonical timestamp": prefix.Clone().
			Append(enc.NewGenericComponent("requester")).
			Append(enc.NewBytesComponent(enc.TypeTimestampNameComponent, []byte{0, 1})),
	}
	for name, requestName := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, m.validateRequestName(requestName, prefix))
		})
	}
}

func TestRejectInvalidRequests(t *testing.T) {
	m := newTestLog(t)
	response, err := m.append(nil)
	require.Error(t, err)
	require.Nil(t, response)

	check, err := m.check([]byte{0x01})
	require.Error(t, err)
	require.Nil(t, check)
}

type failingAppendStore struct {
	merklelog.Store
	err error
}

type checkProducer struct {
	ndn.Client
	store ndn.Store
}

func (c *checkProducer) Produce(args ndn.ProduceArgs) (enc.Name, error) {
	return object.Produce(args, c.store, signer.NewSha256Signer())
}

func makeCheckInterest(t *testing.T, name enc.Name, canBePrefix bool) ndn.Interest {
	t.Helper()
	encoded, err := spec.Spec{}.MakeInterest(
		name,
		&ndn.InterestConfig{CanBePrefix: canBePrefix},
		nil,
		nil,
	)
	require.NoError(t, err)
	interest, _, err := spec.Spec{}.ReadInterest(enc.NewWireView(encoded.Wire))
	require.NoError(t, err)
	return interest
}

func (s *failingAppendStore) Append(merklelog.StoreAppend) error {
	return s.err
}

func newTestLog(t *testing.T) *Log {
	t.Helper()
	name, err := enc.NameFromStr("/operator/merkle")
	require.NoError(t, err)
	m := NewLog(&Config{nameN: name})
	m.tree = merklelog.NewTree()
	m.now = func() time.Time { return time.UnixMilli(1700000000000) }
	return m
}

func apiTestHash(index byte) []byte {
	hash := sha256.Sum256([]byte{index})
	return hash[:]
}
