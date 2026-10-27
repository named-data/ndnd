package nfdc

import (
	"encoding/json"
	"testing"

	dvconfig "github.com/named-data/ndnd/dv/config"
	dvtlv "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/stretchr/testify/require"
)

func TestNDNdStatusJSONFields(t *testing.T) {
	zero := uint64(0)
	report := &ndndStatusReport{
		GeneratedAt: "2026-10-26T00:00:00Z",
		General:     ndndGeneralStatus{NInData: ^uint64(0), NFIBEntries: 3},
		Faces:       ndndFaces{Entries: []ndndFace{{ID: 7, MTU: &zero, NInBytes: 1<<53 + 1}}},
		FIB: ndndFIB{Entries: []ndndFIBEntry{{Prefix: "/app/data",
			NextHops: []ndndNextHop{{FaceID: 7, Cost: ^uint64(0)}},
		}}},
		ContentStore: ndndContentStore{Capacity: 1000, Entries: 2, Hits: ^uint64(0)},
		RIB: ndndRIB{Entries: []ndndRIBEntry{{Prefix: "/app/data",
			Routes: []ndndRoute{{FaceID: 7, Cost: ^uint64(0), ExpirationMillis: &zero}},
		}}},
		DV: ndndDVStatus{Available: true, DatasetAvailable: true, NNeighbors: 1, NPsdEntries: 3,
			Routers: []ndndDVRouter{{Name: "/example/a", Cost: 2, Prefixes: []ndndDVPrefix{{Name: "/app/data", Multicast: true, NotBefore: "20260101T000000", NotAfter: "20990101T000000"}}}},
		},
	}
	wire, err := encodeNdndStatusJSON(report)
	require.NoError(t, err)
	var parsed ndndStatusReport
	require.NoError(t, json.Unmarshal(wire, &parsed))
	require.Equal(t, report, &parsed)
	var document map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(wire, &document))
	require.Contains(t, document, "generatedAt")
	require.NotContains(t, document, "XMLName")
	var general map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(document["general"], &general))
	require.Equal(t, `"18446744073709551615"`, string(general["nInData"]))
	require.Equal(t, `"0"`, string(general["nInInterests"]))
	require.Equal(t, "3", string(general["nFibEntries"]))
	var faces struct {
		Entries []map[string]json.RawMessage `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(document["faces"], &faces))
	require.Equal(t, `"7"`, string(faces.Entries[0]["faceId"]))
	require.Equal(t, `"9007199254740993"`, string(faces.Entries[0]["nInBytes"]))
	require.Equal(t, "0", string(faces.Entries[0]["mtu"]))
	require.NotContains(t, faces.Entries[0], "expirationMilliseconds")
	var dv struct {
		Neighbors json.RawMessage `json:"nNeighbors"`
		Routers   []struct {
			Cost     json.RawMessage `json:"cost"`
			Prefixes []struct {
				Multicast bool `json:"multicast"`
			} `json:"prefixes"`
		} `json:"routers"`
	}
	require.NoError(t, json.Unmarshal(document["dv"], &dv))
	require.Equal(t, "2", string(dv.Routers[0].Cost))
	require.True(t, dv.Routers[0].Prefixes[0].Multicast)
	require.Equal(t, "1", string(dv.Neighbors))
	var cs map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(document["contentStore"], &cs))
	require.Equal(t, "1000", string(cs["capacity"]))
	require.Equal(t, "2", string(cs["entries"]))
	require.Equal(t, `"18446744073709551615"`, string(cs["hits"]))
	for _, table := range []struct{ section, routes string }{{"fib", "nextHop"}, {"rib", "route"}} {
		var entries struct {
			Entries []map[string]json.RawMessage `json:"entries"`
		}
		require.NoError(t, json.Unmarshal(document[table.section], &entries))
		var routes []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(entries.Entries[0][table.routes], &routes))
		require.Equal(t, `"18446744073709551615"`, string(routes[0]["cost"]))
		require.Equal(t, `"7"`, string(routes[0]["faceId"]))
		if table.section == "rib" {
			require.Equal(t, "0", string(routes[0]["expirationMilliseconds"]))
		}
	}
}

func TestStatusReportRejectsInvalidFormatBeforeConnecting(t *testing.T) {
	tool := Tool{statusFormat: "yaml"}
	require.ErrorContains(t, tool.RunStatusReport(nil, nil), "unsupported status format")
	require.Nil(t, tool.engine)
}

func TestDVRoutingDatasetCostBounds(t *testing.T) {
	router := statusTrustName(t, "/example/a")
	prefix := statusTrustName(t, "/app/data")
	for _, tc := range []struct {
		name       string
		routerCost uint64
		err        string
	}{
		{"zero", 0, ""},
		{"maximum-reachable", dvconfig.CostInfinity - 1, ""},
		{"router-infinity", dvconfig.CostInfinity, "router cost"},
		{"router-max-uint64", ^uint64(0), "router cost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataset := &dvtlv.RoutingStatus{
				Status: &dvtlv.Status{RouterName: &dvtlv.Destination{Name: router}},
				Routers: []*dvtlv.RouterStatus{{Name: router, Cost: tc.routerCost,
					Prefixes: []*dvtlv.PrefixOpAdd{{Name: prefix, Multicast: true}},
				}},
			}
			status, err := ndndDVStatusFromDataset(dataset.Encode(), router)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.False(t, status.DatasetAvailable)
				require.Empty(t, status.Routers)
				return
			}
			require.NoError(t, err)
			require.True(t, status.DatasetAvailable)
			require.Equal(t, tc.routerCost, status.Routers[0].Cost)
		})
	}
}

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
			Prefixes: []*dvtlv.PrefixOpAdd{{Name: prefix, Multicast: true, ValidityPeriod: &spec.ValidityPeriod{NotBefore: "20260101T000000", NotAfter: "20990101T000000"}}},
		}},
	}
	status, err := ndndDVStatusFromDataset(dataset.Encode(), router)
	require.NoError(t, err)
	require.True(t, status.DatasetAvailable)
	require.Equal(t, []ndndDVRouter{{Name: "/example/b", NextHop: "/example/b", Cost: 2,
		Prefixes: []ndndDVPrefix{{Name: "/app/data", Multicast: true, NotBefore: "20260101T000000", NotAfter: "20990101T000000"}},
	}}, status.Routers)
	report := &ndndStatusReport{DV: status}
	html, err := renderNDNdStatusHTML(report)
	require.NoError(t, err)
	require.Contains(t, string(html), "Reachable routers and prefix announcements")
	require.Contains(t, string(html), "/app/data (multicast)")
	xml, err := encodeNdndStatusXML(report)
	require.NoError(t, err)
	require.Contains(t, string(xml), `datasetAvailable="true"`)
	require.Contains(t, string(xml), `<router name="/example/b">`)
	require.Contains(t, string(xml), `<prefix name="/app/data" multicast="true" notBefore="20260101T000000" notAfter="20990101T000000">`)
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
	require.Equal(t, "/localhost/dv/status", dvStatusName().String())
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
