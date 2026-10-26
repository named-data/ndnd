package nfdc

import (
	"testing"

	dvtlv "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/stretchr/testify/require"
)

type statusPacketTestEngine struct {
	ndn.Engine
	express func(*ndn.EncodedInterest, ndn.ExpressCallbackFunc) error
}

func (e statusPacketTestEngine) Express(packet *ndn.EncodedInterest, callback ndn.ExpressCallbackFunc) error {
	return e.express(packet, callback)
}

func TestFetchDVStatusInterestIncludesNonce(t *testing.T) {
	base := engine.NewBasicEngine(face.NewDummyFace())
	tool := Tool{engine: statusPacketTestEngine{Engine: base, express: func(packet *ndn.EncodedInterest, callback ndn.ExpressCallbackFunc) error {
		interest, _, err := base.Spec().ReadInterest(enc.NewWireView(packet.Wire))
		require.NoError(t, err)
		require.True(t, interest.Name().Equal(dvStatusName()))
		require.True(t, interest.Nonce().IsSet(), "NDNd drops Interests without a nonce")
		callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultData})
		return nil
	}}}
	_, err := tool.fetchDataPacket(dvStatusName())
	require.NoError(t, err)
}

func TestNDNdStatusXMLOmitsUnavailableCounters(t *testing.T) {
	report := &ndndStatusReport{
		GeneratedAt: "2026-10-17T00:00:00Z",
		General: ndndGeneralStatus{
			Version:      "test-version",
			NFIBEntries:  2,
			NPITEntries:  3,
			NInInterests: 5,
		},
	}

	encoded, err := encodeNdndStatusXML(report)
	require.NoError(t, err)
	text := string(encoded)
	require.Contains(t, text, "<nFibEntries>2</nFibEntries>")
	require.NotContains(t, text, "nNameTreeEntries")
	require.NotContains(t, text, "nMeasurementsEntries")
	require.NotContains(t, text, "nInNacks")
	require.NotContains(t, text, "nOutNacks")
}

func TestNDNdStatusXMLFields(t *testing.T) {
	expiration := uint64(900)
	markInterval := uint64(1000)
	congestionThreshold := uint64(2000)
	report := &ndndStatusReport{
		Faces: ndndFaces{Entries: []ndndFace{{
			ID:                         7,
			ExpirationMilliseconds:     &expiration,
			BaseCongestionMarkInterval: &markInterval,
			DefaultCongestionThreshold: &congestionThreshold,
		}}},
		Strategies: ndndStrategies{Entries: []ndndStrategy{{
			Prefix:   "/ndn",
			Strategy: "/strategy/example",
		}}},
	}
	encoded, err := encodeNdndStatusXML(report)
	require.NoError(t, err)
	xmlText := string(encoded)
	require.Contains(t, xmlText, `<?xml-stylesheet type="text/xsl" href="ndnd-status.xsl"?>`)

	for _, field := range []string{
		`<strategy prefix="/ndn" strategy="/strategy/example">`,
		`<expirationMilliseconds>900</expirationMilliseconds>`,
		`<baseCongestionMarkInterval>1000</baseCongestionMarkInterval>`,
		`<defaultCongestionThreshold>2000</defaultCongestionThreshold>`,
	} {
		require.Contains(t, xmlText, field)
	}
	require.NotContains(t, xmlText, "nInNacks")
	require.NotContains(t, xmlText, "nOutNacks")
}

func TestNDNdDVStatusFromWire(t *testing.T) {
	status := &dvtlv.Status{
		Version:     "test-version",
		NetworkName: &dvtlv.Destination{Name: enc.Name{enc.NewGenericComponent("ndn")}},
		RouterName:  &dvtlv.Destination{Name: enc.Name{enc.NewGenericComponent("router")}},
		NRibEntries: 3,
		NNeighbors:  2,
		NFibEntries: 4,
	}

	parsed, err := ndndDVStatusFromWire(status.Encode())
	require.NoError(t, err)
	require.Equal(t, ndndDVStatus{
		Available:   true,
		Version:     "test-version",
		NetworkName: "/ndn",
		RouterName:  "/router",
		NRibEntries: 3,
		NNeighbors:  2,
		NFibEntries: 4,
	}, parsed)
}

func TestNDNdDVRoutingDataset(t *testing.T) {
	router, err := enc.NameFromStr("/example/a")
	require.NoError(t, err)
	nextHop, err := enc.NameFromStr("/example/b")
	require.NoError(t, err)
	prefix, err := enc.NameFromStr("/app/data")
	require.NoError(t, err)
	dataset := &dvtlv.RoutingStatus{
		Status: &dvtlv.Status{RouterName: &dvtlv.Destination{Name: router}},
		Routers: []*dvtlv.RouterStatus{{
			Name: nextHop, NextHop: &dvtlv.Destination{Name: nextHop}, Cost: 2,
			Prefixes: []*dvtlv.PrefixOpAdd{{Name: prefix, Cost: 7}},
		}},
	}
	status, err := ndndDVStatusFromDataset(dataset.Encode(), router)
	require.NoError(t, err)
	require.True(t, status.DatasetAvailable)
	require.Equal(t, []ndndDVRouter{{Name: "/example/b", NextHop: "/example/b", Cost: 2,
		Prefixes: []ndndDVPrefix{{Name: "/app/data", Cost: 7}},
	}}, status.Routers)
	report := &ndndStatusReport{DV: status}
	html, err := renderNDNdStatusHTML(report)
	require.NoError(t, err)
	require.Contains(t, string(html), "Reachable routers and prefix announcements")
	require.Contains(t, string(html), "/app/data (cost 7)")
	xml, err := encodeNdndStatusXML(report)
	require.NoError(t, err)
	require.Contains(t, string(xml), `datasetAvailable="true"`)
	require.Contains(t, string(xml), `<router name="/example/b">`)
	require.Contains(t, string(xml), `<prefix name="/app/data" cost="7">`)
	_, err = ndndDVStatusFromDataset(dataset.Encode(), nextHop)
	require.ErrorContains(t, err, "requested router")
	_, err = ndndDVStatusFromDataset((&dvtlv.RoutingStatus{}).Encode(), router)
	require.Error(t, err)
}

func TestNDNdDVRoutingDatasetUnavailable(t *testing.T) {
	html, err := renderNDNdStatusHTML(&ndndStatusReport{DV: ndndDVStatus{Available: true}})
	require.NoError(t, err)
	require.Contains(t, string(html), "DV routing dataset unavailable")
	require.NotContains(t, string(html), "No reachable routers")
}

func TestNDNdDVStatusName(t *testing.T) {
	require.Equal(t, "/localhost/nlsr/status", dvStatusName().String())
}

func TestNDNdStatusFaceFlags(t *testing.T) {
	flags := mgmt.FaceFlagLocalFieldsEnabled | mgmt.FaceFlagLpReliabilityEnabled | mgmt.FaceFlagCongestionMarkingEnabled
	require.Equal(t, "local-fields, lp-reliability, congestion-marking", faceFlagsName(flags))
}

func TestNDNdStatusHTMLRenderingEscapesValues(t *testing.T) {
	mtu := uint64(1450)
	expiration := uint64(900)
	report := &ndndStatusReport{
		General: ndndGeneralStatus{Version: `<script>alert("x")</script>`},
		Faces:   ndndFaces{Entries: []ndndFace{{MTU: &mtu, ExpirationMilliseconds: &expiration}}},
		DV:      ndndDVStatus{Available: false},
	}
	encoded, err := renderNDNdStatusHTML(report)
	require.NoError(t, err)
	html := string(encoded)
	require.Contains(t, html, "<!doctype html>")
	require.Contains(t, html, "NDNd Status")
	require.Contains(t, html, `&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;`)
	require.NotContains(t, html, `<script>alert("x")</script>`)
	require.Contains(t, html, ">1450</td>")
	require.Contains(t, html, ">900</td>")
	require.NotContains(t, html, "0x")
	require.Contains(t, html, "DV status unavailable")
}

func TestNDNdContentStoreMissingPayload(t *testing.T) {
	report, err := ndndContentStoreFromStatus(&mgmt.CsInfoMsg{})
	require.ErrorContains(t, err, "no CsInfo payload")
	require.Equal(t, ndndContentStore{}, report)
}

func TestNDNdContentStoreStatusMapping(t *testing.T) {
	report, err := ndndContentStoreFromStatus(&mgmt.CsInfoMsg{CsInfo: &mgmt.CsInfo{
		Capacity:   1024,
		Flags:      mgmt.CsEnableAdmit,
		NCsEntries: 12,
		NHits:      34,
		NMisses:    56,
	}})
	require.NoError(t, err)
	require.Equal(t, ndndContentStore{
		Capacity: 1024,
		Admit:    true,
		Serve:    false,
		Entries:  12,
		Hits:     34,
		Misses:   56,
	}, report)
}
