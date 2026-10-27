package dv

import (
	"fmt"
	"testing"
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/trust_schema"
	"github.com/stretchr/testify/require"
)

// Transport real encoded packets through a serialized engine queue, with only
// the dataset prefix routable. Certificate Interests must use a forwarding hint.
type statusDatasetConsumerEngine struct {
	ndn.Engine
	queue      chan func()
	handler    ndn.InterestHandler
	dataPrefix enc.Name
}

func (e *statusDatasetConsumerEngine) Post(fn func()) { e.queue <- fn }

func (e *statusDatasetConsumerEngine) Express(packet *ndn.EncodedInterest, callback ndn.ExpressCallbackFunc) error {
	interest, covered, err := e.Spec().ReadInterest(enc.NewWireView(packet.Wire))
	if err != nil {
		return err
	}
	routed := e.dataPrefix.IsPrefix(interest.Name())
	for _, hint := range interest.ForwardingHint() {
		routed = routed || e.dataPrefix.IsPrefix(hint)
	}
	if !routed {
		e.Post(func() {
			callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultError, Error: fmt.Errorf("no route for certificate Interest")})
		})
		return nil
	}
	e.Post(func() {
		e.handler(ndn.InterestHandlerArgs{Interest: interest, SigCovered: covered, Reply: func(wire enc.Wire) error {
			data, sigCovered, err := e.Spec().ReadData(enc.NewWireView(wire))
			if err != nil {
				return err
			}
			e.Post(func() {
				callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultData, Data: data, RawData: wire, SigCovered: sigCovered})
			})
			return nil
		}})
	})
	return nil
}

func TestRoutingStatusRemoteValidation(t *testing.T) {
	for _, hint := range []bool{false, true} {
		t.Run(fmt.Sprintf("forwarding-hint=%t", hint), func(t *testing.T) {
			router, _ := newStatusTestRouter(t)
			addStatusTestPrefixes(t, router, 1000)
			prefix := config.StatusDatasetPrefix(router.config.RouterName())
			transport := &statusDatasetConsumerEngine{
				Engine: router.engine, queue: make(chan func(), 512),
				dataPrefix: prefix, handler: router.onStatusDataset,
			}
			// The consumer initially knows only the root, so validation must
			// fetch the producer's certificate rather than use its keychain.
			consumerStore := storage.NewMemoryStore()
			kc := keychain.NewKeyChainMem(consumerStore)
			anchors := router.config.TrustAnchorNames()
			rootWire, err := router.client.Store().Get(anchors[0], false)
			require.NoError(t, err)
			require.NoError(t, kc.InsertCert(rootWire))
			schema, err := trust_schema.NewLvsSchema(config.SchemaBytes)
			require.NoError(t, err)
			trust, err := sec.NewTrustConfig(kc, schema, anchors)
			require.NoError(t, err)
			trust.UseDataNameFwHint = hint
			consumer := object.NewClient(transport, consumerStore, trust)
			stop, stopped := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(stopped)
				for {
					select {
					case fn := <-transport.queue:
						fn()
					case <-stop:
						return
					}
				}
			}()
			defer func() { close(stop); <-stopped }()
			result := make(chan ndn.ConsumeState, 1)
			consumer.Consume(prefix, func(state ndn.ConsumeState) { result <- state })
			select {
			case state := <-result:
				if !hint {
					require.ErrorContains(t, state.Error(), "no route for certificate Interest")
					return
				}
				require.NoError(t, state.Error())
				dataset, err := tlv.ParseRoutingStatus(enc.NewWireView(state.Content()), false)
				require.NoError(t, err)
				require.Len(t, dataset.Routers, 1)
				require.True(t, router.config.RouterName().Equal(dataset.Status.RouterName.Name))
				require.Len(t, dataset.Routers[0].Prefixes, 1000)
			case <-time.After(5 * time.Second):
				t.Fatal("remote validation did not complete")
			}
		})
	}
}
