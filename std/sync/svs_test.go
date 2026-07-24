package sync

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/assert"
)

// MockClient is a stub implementation of the Client interface.
type MockClient struct{}

func (m *MockClient) String() string {
	return "mock-client"
}

func (m *MockClient) Start() error {
	return nil
}

func (m *MockClient) Stop() error {
	return nil
}

func (m *MockClient) Engine() ndn.Engine {
	return nil
}

func (m *MockClient) Store() ndn.Store {
	return nil
}

func (m *MockClient) Produce(args ndn.ProduceArgs) (enc.Name, error) {
	return nil, nil
}

func (m *MockClient) Remove(name enc.Name) error {
	return nil
}

func (m *MockClient) Consume(name enc.Name, callback func(status ndn.ConsumeState)) {
}

func (m *MockClient) ConsumeExt(args ndn.ConsumeExtArgs) {}

func (m *MockClient) LatestLocal(name enc.Name) (enc.Name, error) {
	return nil, nil
}

func (m *MockClient) GetLocal(name enc.Name) (enc.Wire, error) {
	return nil, nil
}

func (m *MockClient) ExpressR(args ndn.ExpressRArgs) {}

func (m *MockClient) IsCongested() bool {
	return false
}

func (m *MockClient) SuggestSigner(name enc.Name) ndn.Signer {
	return nil
}

func (m *MockClient) Validate(data ndn.Data, sigCov enc.Wire, callback func(bool, error)) {}

func (m *MockClient) ValidateExt(args ndn.ValidateExtArgs) {}

func (m *MockClient) SetTrustSchema(schema ndn.TrustSchema) {}

func (m *MockClient) PromoteTrustAnchor(cert ndn.Data, raw enc.Wire) {}

func (m *MockClient) AnnouncePrefix(args ndn.Announcement) {}

func (m *MockClient) WithdrawPrefix(name enc.Name, onError func(error)) {}

func (m *MockClient) AttachCommandHandler(name enc.Name, handler func(name enc.Name, content enc.Wire, reply func(enc.Wire) error)) error {
	return nil
}

func (m *MockClient) DetachCommandHandler(name enc.Name) error {
	return nil
}

func (m *MockClient) ExpressCommand(dest enc.Name, name enc.Name, cmd enc.Wire, callback func(enc.Wire, error)) {
}

func TestSvSync_SyncPrefix(t *testing.T) {
	tu.SetT(t)

	sv := NewSvSync(SvSyncOpts{
		Client:      &MockClient{},
		GroupPrefix: tu.NoErr(enc.NameFromStr("/G")),
		OnUpdate:    func(ssu SvSyncUpdate) {},
	})

	assert.True(t, sv.SyncPrefix().Equal(tu.NoErr(enc.NameFromStr("/G/v=3"))))
}
