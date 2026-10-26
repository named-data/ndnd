package nfdc

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	dvconfig "github.com/named-data/ndnd/dv/config"
	dvtlv "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/stretchr/testify/require"
)

func statusTrustName(t *testing.T, value string) enc.Name {
	t.Helper()
	name, err := enc.NameFromStr(value)
	require.NoError(t, err)
	return name
}

func statusTrustProducer(t *testing.T, router string, prefixCost uint64) (ndn.Store, []byte) {
	t.Helper()
	store := storage.NewMemoryStore()
	rootKey, err := signer.KeygenEd25519(sec.MakeKeyName(statusTrustName(t, "/example")))
	require.NoError(t, err)
	before, after := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	root, err := sec.SelfSign(sec.SignCertArgs{Signer: rootKey, NotBefore: before, NotAfter: after})
	require.NoError(t, err)
	key, err := signer.KeygenEd25519(sec.MakeKeyName(statusTrustName(t, router+"/32=DV")))
	require.NoError(t, err)
	secret, err := signer.MarshalSecretToData(key)
	require.NoError(t, err)
	cert, err := sec.SignCert(sec.SignCertArgs{Signer: rootKey, Data: secret,
		IssuerId: enc.NewGenericComponent("network"), NotBefore: before, NotAfter: after})
	require.NoError(t, err)
	for _, wire := range []enc.Wire{root, cert} {
		data, _, err := (spec.Spec{}).ReadData(enc.NewWireView(wire))
		require.NoError(t, err)
		require.NoError(t, store.Put(data.Name(), wire.Join()))
	}
	requested := statusTrustName(t, "/example/a")
	status := &dvtlv.Status{Version: "test", NetworkName: &dvtlv.Destination{Name: statusTrustName(t, "/example")},
		RouterName: &dvtlv.Destination{Name: requested}}
	dataset := &dvtlv.RoutingStatus{Status: status, Routers: []*dvtlv.RouterStatus{{Name: requested}}}
	for i := range 1000 {
		dataset.Routers[0].Prefixes = append(dataset.Routers[0].Prefixes,
			&dvtlv.PrefixOpAdd{Name: statusTrustName(t, fmt.Sprintf("/application/prefix-%04d", i)), Cost: prefixCost})
	}
	_, err = object.Produce(ndn.ProduceArgs{
		Name: dvconfig.StatusDatasetPrefix(requested).WithVersion(1), Content: dataset.Encode(),
	}, store, key)
	require.NoError(t, err)
	summary, err := (spec.Spec{}).MakeData(dvStatusName(), &ndn.DataConfig{}, status.Encode(), nil)
	require.NoError(t, err)
	require.NoError(t, store.Put(dvStatusName(), summary.Wire.Join()))
	return store, root.Join()
}

// Deliver encoded packets on an engine queue. Only management and dataset
// names are routable; certificate Interests must carry a dataset forwarding hint.
type statusTrustEngine struct {
	ndn.Engine
	store            ndn.Store
	queue            chan func()
	tamper           string
	metadataRequests int
	tamperedSegments []uint64
}

func (e *statusTrustEngine) Post(fn func()) { e.queue <- fn }

func (e *statusTrustEngine) Express(packet *ndn.EncodedInterest, callback ndn.ExpressCallbackFunc) error {
	interest, _, err := e.Spec().ReadInterest(enc.NewWireView(packet.Wire))
	if err != nil {
		return err
	}
	e.Post(func() {
		prefix, _ := enc.NameFromStr("/example/a/32=DV/32=STATUS")
		name := interest.Name()
		routed := name.Equal(dvStatusName()) || prefix.IsPrefix(name)
		for _, hint := range interest.ForwardingHint() {
			routed = routed || prefix.IsPrefix(hint)
		}
		if !routed {
			callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultError, Error: fmt.Errorf("no certificate route")})
			return
		}
		if name.At(-1).IsKeyword("metadata") {
			e.metadataRequests++
		}
		wire, err := e.store.Get(name, interest.CanBePrefix())
		if err != nil || wire == nil {
			callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultError, Error: fmt.Errorf("packet unavailable")})
			return
		}
		tamperSegment := name.At(-1).IsSegment() &&
			((e.tamper == "segment-0" && name.At(-1).NumberVal() == 0) ||
				(e.tamper == "segment-1" && name.At(-1).NumberVal() == 1))
		if prefix.IsPrefix(name) && ((e.tamper == "metadata" && name.At(-1).IsKeyword("metadata")) || tamperSegment) {
			wire = append([]byte(nil), wire...)
			wire[len(wire)-1] ^= 1 // Change the signature while keeping the TLV well formed.
			if tamperSegment {
				e.tamperedSegments = append(e.tamperedSegments, name.At(-1).NumberVal())
			}
		}
		data, covered, err := e.Spec().ReadData(enc.NewBufferView(wire))
		if err != nil {
			callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultError, Error: err})
			return
		}
		callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultData, Data: data, SigCovered: covered, RawData: enc.Wire{wire}})
	})
	return nil
}

func TestStatusReportValidatesDVDataset(t *testing.T) {
	for _, scenario := range []string{"valid", "metadata", "segment-0", "segment-1", "wrong-router", "untrusted-root", "no-anchors", "invalid-cost"} {
		t.Run(scenario, func(t *testing.T) {
			router := "/example/a"
			if scenario == "wrong-router" {
				router = "/example/b"
			}
			cost := uint64(0)
			if scenario == "invalid-cost" {
				cost = 1<<53 + 1
			}
			store, root := statusTrustProducer(t, router, cost)
			if scenario == "untrusted-root" {
				_, root = statusTrustProducer(t, "/example/a", 0)
			}
			transport := &statusTrustEngine{Engine: engine.NewBasicEngine(face.NewDummyFace()),
				store: store, queue: make(chan func(), 512), tamper: scenario}
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
			tool := Tool{engine: transport}
			if scenario != "no-anchors" {
				path := filepath.Join(t.TempDir(), "root.cert")
				pem, err := sec.PemEncode(root)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, pem, 0600))
				tool.statusTrustAnchors = []string{path}
			}
			require.NoError(t, tool.configureStatusTrust())
			report := ndndStatusReport{General: ndndGeneralStatus{NFIBEntries: 7}}
			err := tool.populateDVStatus(&report)
			if scenario == "valid" || scenario == "no-anchors" {
				require.NoError(t, err)
			} else if scenario == "invalid-cost" {
				require.ErrorContains(t, err, "parse DV routing dataset")
				require.ErrorContains(t, err, "prefix cost")
			} else {
				require.ErrorContains(t, err, "fetch or validate DV routing dataset")
			}
			require.True(t, report.DV.Available)
			require.Equal(t, uint64(7), report.General.NFIBEntries)
			require.Equal(t, scenario == "valid", report.DV.DatasetAvailable)
			if scenario == "valid" {
				require.Len(t, report.DV.Routers[0].Prefixes, 1000)
			} else {
				require.Empty(t, report.DV.Routers)
			}
			if scenario == "no-anchors" {
				require.Zero(t, transport.metadataRequests)
			}
			if scenario == "segment-0" || scenario == "segment-1" {
				require.ErrorContains(t, err, "validate seg failed")
				segment := uint64(0)
				if scenario == "segment-1" {
					segment = 1
				}
				require.Equal(t, []uint64{segment}, transport.tamperedSegments)
			}
		})
	}
}

func TestStatusTrustRejectsInvalidFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.cert")
	tool := Tool{statusTrustAnchors: []string{path}}
	require.Error(t, tool.configureStatusTrust())
	for _, content := range [][]byte{nil, []byte("not a certificate")} {
		require.NoError(t, os.WriteFile(path, content, 0600))
		require.Error(t, tool.configureStatusTrust())
		require.Nil(t, tool.statusTrust)
	}
}
