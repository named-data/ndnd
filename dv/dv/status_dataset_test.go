package dv

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	"github.com/named-data/ndnd/dv/table"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/security/trust_schema"
	"github.com/stretchr/testify/require"
)

func statusTestName(t *testing.T, name string) enc.Name {
	t.Helper()
	result, err := enc.NameFromStr(name)
	require.NoError(t, err)
	return result
}

func newStatusTestRouter(t *testing.T) (*Router, ndn.Data) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Network, cfg.Router = "/example", "/example/a"
	dir := t.TempDir()
	kc, err := keychain.NewKeyChainDir(dir, storage.NewMemoryStore())
	require.NoError(t, err)
	rootKey, err := signer.KeygenEd25519(sec.MakeKeyName(statusTestName(t, cfg.Network)))
	require.NoError(t, err)
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	rootWire, err := sec.SelfSign(sec.SignCertArgs{Signer: rootKey, NotBefore: notBefore, NotAfter: notAfter})
	require.NoError(t, err)
	root, _, err := (spec.Spec{}).ReadData(enc.NewWireView(rootWire))
	require.NoError(t, err)
	require.NoError(t, kc.InsertCert(rootWire.Join()))
	identity := statusTestName(t, cfg.Router).Append(enc.NewKeywordComponent("DV"))
	key, err := signer.KeygenEd25519(sec.MakeKeyName(identity))
	require.NoError(t, err)
	secret, err := signer.MarshalSecretToData(key)
	require.NoError(t, err)
	certWire, err := sec.SignCert(sec.SignCertArgs{
		Signer: rootKey, Data: secret, IssuerId: enc.NewGenericComponent("network"),
		NotBefore: notBefore, NotAfter: notAfter,
	})
	require.NoError(t, err)
	require.NoError(t, kc.InsertKey(key))
	require.NoError(t, kc.InsertCert(certWire.Join()))
	cfg.KeyChainUri = "dir://" + dir
	cfg.TrustSchemaPath = "../config/schema.tlv"
	cfg.TrustAnchors = []string{root.Name().String()}
	router, err := NewRouter(cfg, engine.NewBasicEngine(face.NewDummyFace()))
	require.NoError(t, err)
	cert, _, err := (spec.Spec{}).ReadData(enc.NewWireView(certWire))
	require.NoError(t, err)
	router.rib.Set(cfg.RouterName(), cfg.RouterName(), 0)
	return router, cert
}

func queryStatusPacket(t *testing.T, router *Router, name enc.Name, prefix bool) ndn.Data {
	t.Helper()
	packet, err := (spec.Spec{}).MakeInterest(name, &ndn.InterestConfig{CanBePrefix: prefix}, nil, nil)
	require.NoError(t, err)
	interest, _, err := (spec.Spec{}).ReadInterest(enc.NewWireView(packet.Wire))
	require.NoError(t, err)
	reply := make(chan enc.Wire, 1)
	router.onStatusDataset(ndn.InterestHandlerArgs{Interest: interest, Reply: func(wire enc.Wire) error { reply <- wire; return nil }})
	select {
	case wire := <-reply:
		data, _, err := (spec.Spec{}).ReadData(enc.NewWireView(wire))
		require.NoError(t, err)
		return data
	case <-time.After(2 * time.Second):
		t.Fatal("routing status Interest did not receive a reply")
		return nil
	}
}

func TestRoutingStatusSnapshot(t *testing.T) {
	router, _ := newStatusTestRouter(t)
	remote, dead := statusTestName(t, "/example/b"), statusTestName(t, "/example/dead")
	router.rib.Set(remote, remote, 2)
	router.rib.Set(dead, dead, config.CostInfinity)
	prefix := statusTestName(t, "/app/data")
	router.pfx.GetRouter(remote).Prefixes[prefix.TlvStr()] = &table.PrefixEntry{Name: prefix, Multicast: true, ValidityPeriod: &spec.ValidityPeriod{NotAfter: "20990101T000000"}}
	lastPrefix := statusTestName(t, "/z/data")
	router.pfx.GetRouter(remote).Prefixes[lastPrefix.TlvStr()] = &table.PrefixEntry{Name: lastPrefix, Multicast: false}
	snapshot := router.routingStatus()
	require.Len(t, snapshot.Routers, 2)
	require.Equal(t, "/example/a", snapshot.Routers[0].Name.String())
	require.Equal(t, "/example/b", snapshot.Routers[1].Name.String())
	require.Equal(t, uint64(2), snapshot.Routers[1].Cost)
	require.Equal(t, "/example/b", snapshot.Routers[1].NextHop.Name.String())
	require.True(t, snapshot.Routers[1].Prefixes[1].Multicast)
	require.Equal(t, "20990101T000000", snapshot.Routers[1].Prefixes[1].ValidityPeriod.NotAfter)
	require.Equal(t, uint64(2), snapshot.Status.NPsdEntries)
	require.Len(t, snapshot.Routers[1].Prefixes, 2)
	// NDN canonical ordering compares component lengths before their bytes.
	require.Equal(t, "/z/data", snapshot.Routers[1].Prefixes[0].Name.String())
	// Snapshots must own their names after the live-table mutex is released.
	prefix[0].Val[0] = 'X'
	router.pfx.GetRouter(remote).Prefixes[statusTestName(t, "/app/data").TlvStr()].ValidityPeriod.NotAfter = "20000101T000000"
	require.Equal(t, "/app/data", snapshot.Routers[1].Prefixes[1].Name.String())
	require.Equal(t, "20990101T000000", snapshot.Routers[1].Prefixes[1].ValidityPeriod.NotAfter)
	wire := snapshot.Encode()
	parsed, err := tlv.ParseRoutingStatus(enc.NewWireView(wire), false)
	require.NoError(t, err)
	require.Equal(t, snapshot, parsed)
}

func addStatusTestPrefixes(t *testing.T, router *Router, count int) {
	t.Helper()
	entries := router.pfx.GetRouter(router.config.RouterName()).Prefixes
	for i := range count {
		name := statusTestName(t, fmt.Sprintf("/application/long-prefix-%04d", i))
		entries[name.TlvStr()] = &table.PrefixEntry{Name: name, Multicast: i%2 == 0}
	}
}

func TestRoutingStatusSegmentedAndSigned(t *testing.T) {
	router, cert := newStatusTestRouter(t)
	addStatusTestPrefixes(t, router, 1000)
	prefix := config.StatusDatasetPrefix(router.config.RouterName())
	metadataName := prefix.Append(enc.NewKeywordComponent(rdr.MetadataKeyword))
	metadata := queryStatusPacket(t, router, metadataName, true)
	meta, err := rdr.ParseMetaData(enc.NewWireView(metadata.Content()), false)
	require.NoError(t, err)
	first := queryStatusPacket(t, router, meta.Name.Append(enc.NewSegmentComponent(0)), false)
	last := first.FinalBlockID().Unwrap().NumberVal()
	require.Positive(t, last)
	var content enc.Wire
	for i := uint64(0); i <= last; i++ {
		packet := queryStatusPacket(t, router, meta.Name.Append(enc.NewSegmentComponent(i)), false)
		stored, err := router.client.Store().Get(packet.Name(), false)
		require.NoError(t, err)
		_, covered, err := (spec.Spec{}).ReadData(enc.NewBufferView(stored))
		require.NoError(t, err)
		valid, err := signer.ValidateData(packet, covered, cert)
		require.NoError(t, err)
		require.True(t, valid)
		content = append(content, packet.Content()...)
	}
	status, err := tlv.ParseRoutingStatus(enc.NewWireView(content), false)
	require.NoError(t, err)
	require.Len(t, status.Routers[0].Prefixes, 1000)
	// Another discovery within the freshness interval uses the same object.
	again := queryStatusPacket(t, router, metadataName, true)
	require.True(t, metadata.Name().Equal(again.Name()))
	require.Equal(t, 1, router.statusObjects.Count())
}

func TestRoutingStatusSchema(t *testing.T) {
	router, cert := newStatusTestRouter(t)
	schema, err := trust_schema.NewLvsSchema(config.SchemaBytes)
	require.NoError(t, err)
	require.True(t, schema.Check(config.StatusDatasetPrefix(router.config.RouterName()), cert.Name()))
	require.False(t, schema.Check(config.StatusDatasetPrefix(statusTestName(t, "/example/b")), cert.Name()))
	require.True(t, schema.Check(router.config.AdvertisementDataPrefix().Append(enc.NewTimestampComponent(1)), cert.Name()))
	selected := router.client.SuggestSigner(config.StatusDatasetPrefix(router.config.RouterName()))
	require.NotNil(t, selected)
	keyName, err := sec.GetKeyNameFromCertName(cert.Name())
	require.NoError(t, err)
	require.True(t, keyName.Equal(selected.KeyName()))
	require.Nil(t, router.client.SuggestSigner(config.StatusDatasetPrefix(statusTestName(t, "/example/b"))))
}

func TestRoutingStatusConcurrentUpdates(t *testing.T) {
	router, _ := newStatusTestRouter(t)
	remote := statusTestName(t, "/example/b")
	var work sync.WaitGroup
	work.Add(2)
	go func() {
		defer work.Done()
		for i := range 100 {
			router.mutex.Lock()
			router.rib.Set(remote, remote, uint64(i%3+1))
			router.mutex.Unlock()
		}
	}()
	prefix := statusTestName(t, "/app/concurrent")
	go func() {
		defer work.Done()
		for i := range 100 {
			router.pfx.mu.Lock()
			router.pfx.pfx.GetRouter(remote).Prefixes[prefix.TlvStr()] = &table.PrefixEntry{Name: prefix.Clone(), Multicast: i%2 == 0}
			router.pfx.mu.Unlock()
		}
	}()
	for range 100 {
		_ = router.routingStatus().Encode()
	}
	work.Wait()
}

type statusRouteTestEngine struct {
	ndn.Engine
	commands chan nfdc.NfdMgmtCmd
}

func (e statusRouteTestEngine) ExecMgmtCmd(module, cmd string, args any) (any, error) {
	e.commands <- nfdc.NfdMgmtCmd{Module: module, Cmd: cmd, Args: args.(*mgmt.ControlArgs)}
	return nil, nil
}

func TestRoutingStatusRoutesAcrossMultipleHops(t *testing.T) {
	router, _ := newStatusTestRouter(t)
	commands := make(chan nfdc.NfdMgmtCmd, 64)
	router.nfdc = nfdc.NewNfdMgmtThread(statusRouteTestEngine{router.engine, commands})
	router.neighbors = table.NewNeighborTable(router.config, router.nfdc)
	router.fib = table.NewFib(router.config, router.nfdc)
	stopped := make(chan struct{})
	go func() { router.nfdc.Start(); close(stopped) }()
	defer func() { router.nfdc.Stop(); <-stopped }()

	neighbor := statusTestName(t, "/example/b")
	remote := statusTestName(t, "/example/c")
	_, _ = router.neighbors.Add(neighbor).RecvPing(7, true)
	router.rib.Set(neighbor, neighbor, 1)
	router.rib.Set(remote, neighbor, 2)
	router.updateFib()
	prefix := config.StatusDatasetPrefix(remote)
	waitFor := func(command string) *mgmt.ControlArgs {
		t.Helper()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case got := <-commands:
				if got.Module == "pet" && got.Cmd == command && got.Args.Name.Equal(prefix) {
					return got.Args
				}
			case <-deadline.C:
				t.Fatalf("missing dataset route %s", command)
				return nil
			}
		}
	}
	registered := waitFor("add-egress")
	require.True(t, remote.Equal(registered.Egress.Name))
	router.rib.RemoveNextHop(neighbor)
	router.rib.Prune()
	router.updateFib()
	require.True(t, remote.Equal(waitFor("remove-egress").Egress.Name))
}
