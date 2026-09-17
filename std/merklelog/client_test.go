package merklelog

import (
	"crypto/sha256"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/require"
)

func TestClientAppend(t *testing.T) {
	hash := clientTestHash(0)
	mock := &commandClientMock{
		response: (&defn.AppendResponse{Results: []*defn.AppendResult{{
			DataHash:  hash,
			Status:    defn.AppendStatusOK,
			LeafIndex: optional.Some(uint64(7)),
		}}}).Encode(),
	}
	logPrefix := clientTestName(t, "/operator/merkle")
	requester := clientTestName(t, "/requester")
	client, err := NewClient(mock, logPrefix, requester)
	require.NoError(t, err)
	client.now = func() time.Time { return time.UnixMilli(1700000000000) }

	var response *defn.AppendResponse
	client.Append([][]byte{hash}, func(ret *defn.AppendResponse, err error) {
		require.NoError(t, err)
		response = ret
	})
	require.NotNil(t, response)
	require.Equal(t, uint64(7), response.Results[0].LeafIndex.Unwrap())
	require.True(t, mock.dest.Equal(AppendPrefix(logPrefix)))
	require.True(t, AppendPrefix(logPrefix).IsPrefix(mock.name))
	require.Equal(t, requester, mock.name[len(AppendPrefix(logPrefix)):len(mock.name)-1])
	require.True(t, mock.name.At(-1).IsTimestamp())
	require.Equal(t, uint64(1700000000000), mock.name.At(-1).NumberVal())

	request, err := defn.ParseAppendRequest(enc.NewWireView(mock.command), false)
	require.NoError(t, err)
	require.Equal(t, [][]byte{hash}, request.DataHashes)
}

func TestClientCheckVerifiesProof(t *testing.T) {
	hash := clientTestHash(0)
	tree := NewTree()
	entryWire, err := EncodeLogEntry(&defn.LogEntry{
		IngestTime: time.Second,
		DataHashes: [][]byte{hash},
	})
	require.NoError(t, err)
	_, err = tree.Append(entryWire)
	require.NoError(t, err)
	proof, err := tree.InclusionProof(0)
	require.NoError(t, err)

	mock := &commandClientMock{
		response: (&defn.CheckResponse{
			Root: tree.Root(),
			Result: &defn.CheckResult{
				DataHash: hash,
				Status:   defn.CheckStatusIncluded,
				Proof:    proof,
			},
		}).Encode(),
		responseVersion: tree.Size(),
	}
	client, err := NewClient(
		mock,
		clientTestName(t, "/operator/merkle"),
		clientTestName(t, "/requester"),
	)
	require.NoError(t, err)

	var response *defn.CheckResponse
	client.Check(hash, func(ret *defn.CheckResponse, err error) {
		require.NoError(t, err)
		response = ret
	})
	require.NotNil(t, response)
	require.NoError(t, VerifyInclusion(hash, response.Result.Proof, response.Root))
	checkName := CheckPrefix(clientTestName(t, "/operator/merkle")).
		Append(enc.NewGenericBytesComponent(hash))
	require.True(t, checkName.Equal(mock.consumeName))
	require.Equal(t, enc.TypeGenericNameComponent, mock.consumeName.At(-1).Typ)
}

func TestClientRejectsInvalidResponses(t *testing.T) {
	hash := clientTestHash(0)

	require.Error(t, validateAppendResponse([][]byte{hash}, &defn.AppendResponse{
		Results: []*defn.AppendResult{{
			DataHash: hash,
			Status:   defn.AppendStatusOK,
		}},
	}))
	require.Error(t, validateCheckResponse(hash, &defn.CheckResponse{
		Root: &defn.TreeRoot{RootHash: make([]byte, HashSize)},
		Result: &defn.CheckResult{
			DataHash: hash,
			Status:   defn.CheckStatusIncluded,
		},
	}))
	require.Error(t, validateCheckResponse(hash, &defn.CheckResponse{
		Root: &defn.TreeRoot{RootHash: make([]byte, HashSize)},
		Result: &defn.CheckResult{
			DataHash: hash,
			Status:   defn.CheckStatusNotFound,
		},
	}))
}

type commandClientMock struct {
	ndn.Client
	dest            enc.Name
	name            enc.Name
	command         enc.Wire
	consumeName     enc.Name
	response        enc.Wire
	responseVersion uint64
	err             error
}

func (m *commandClientMock) ExpressCommand(
	dest enc.Name,
	name enc.Name,
	command enc.Wire,
	callback func(enc.Wire, error),
) {
	m.dest = dest
	m.name = name
	m.command = command
	callback(m.response, m.err)
}

func (m *commandClientMock) ConsumeExt(args ndn.ConsumeExtArgs) {
	m.consumeName = args.Name
	args.Callback(&consumeStateMock{
		name:    args.Name.Append(enc.NewVersionComponent(m.responseVersion)),
		content: m.response,
		err:     m.err,
	})
}

type consumeStateMock struct {
	name    enc.Name
	content enc.Wire
	err     error
}

func (s *consumeStateMock) Name() enc.Name    { return s.name }
func (s *consumeStateMock) Version() uint64   { return s.name.At(-1).NumberVal() }
func (s *consumeStateMock) IsComplete() bool  { return true }
func (s *consumeStateMock) Progress() int     { return 1 }
func (s *consumeStateMock) ProgressMax() int  { return 1 }
func (s *consumeStateMock) Error() error      { return s.err }
func (s *consumeStateMock) Content() enc.Wire { return s.content }
func (s *consumeStateMock) Cancel()           {}

func clientTestName(t *testing.T, value string) enc.Name {
	t.Helper()
	name, err := enc.NameFromStr(value)
	require.NoError(t, err)
	return name
}

func clientTestHash(index byte) []byte {
	hash := sha256.Sum256([]byte{index})
	return hash[:]
}
