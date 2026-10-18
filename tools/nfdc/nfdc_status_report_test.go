package nfdc

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"

	specDV "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/require"
)

type statusResponseEngine struct {
	ndn.Engine
	timer     *basic_engine.DummyTimer
	responses map[string]enc.Wire
}

func (e *statusResponseEngine) Spec() ndn.Spec {
	return spec_2022.Spec{}
}

func (e *statusResponseEngine) Timer() ndn.Timer {
	return e.timer
}

func (e *statusResponseEngine) Express(interest *ndn.EncodedInterest, callback ndn.ExpressCallbackFunc) error {
	content, ok := e.responses[interest.FinalName.String()]
	if !ok {
		return fmt.Errorf("unexpected management query %s", interest.FinalName)
	}
	packet, err := (spec_2022.Spec{}).MakeData(interest.FinalName, &ndn.DataConfig{}, content, nil)
	if err != nil {
		return err
	}
	data, _, err := (spec_2022.Spec{}).ReadData(enc.NewWireView(packet.Wire))
	if err != nil {
		return err
	}
	callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultData, Data: data, RawData: packet.Wire})
	return nil
}

func TestNDNdStatusXMLOmitsUnavailableNFDFields(t *testing.T) {
	report := &ndndStatusReport{
		GeneratedAt: "2026-10-17T00:00:00Z",
		DVState:     "unavailable",
		General: ndndGeneralStatus{
			Version:      "test-version",
			NFIBEntries:  2,
			NPITEntries:  3,
			NInInterests: 4,
		},
	}

	encoded, err := encodeNdndStatusXML(report)
	require.NoError(t, err)
	text := string(encoded)
	require.Contains(t, text, "<nFibEntries>2</nFibEntries>")
	require.Contains(t, text, `dvState="unavailable"`)
	require.NotContains(t, text, "nNameTreeEntries")
	require.NotContains(t, text, "nMeasurementsEntries")
	require.NotContains(t, text, "nInNacks")
	require.NotContains(t, text, "nOutNacks")
	require.False(t, strings.Contains(text, "<nOutBytes>"))
}

func TestNDNdStatusXMLFields(t *testing.T) {
	expiration := uint64(900)
	report := &ndndStatusReport{
		Faces: ndndFaces{Entries: []ndndFace{{
			ID:                     7,
			ExpirationMilliseconds: &expiration,
		}}},
		Strategies: ndndStrategies{Entries: []ndndStrategy{{
			Prefix:   "/ndn",
			Strategy: "/strategy/example",
		}}},
		DV: &ndndDVStatus{
			PrefixListState: "available",
			Prefixes: []ndndDVPrefixEntry{{
				Prefix:   "/ndn/example",
				Validity: &ndndDVValidity{NotAfter: "2027-01-01T00:00:00Z"},
			}, {
				Prefix:   "/ndn/other",
				Validity: &ndndDVValidity{NotBefore: "2026-01-01T00:00:00Z"},
			}},
		},
	}
	encoded, err := encodeNdndStatusXML(report)
	require.NoError(t, err)
	xmlText := string(encoded)
	require.Contains(t, xmlText, `<?xml-stylesheet type="text/xsl" href="ndnd-status.xsl"?>`)
	require.NotContains(t, xmlText, "ndnd-status-polyfill.min.js")

	for _, field := range []string{
		`<strategy prefix="/ndn" strategy="/strategy/example">`,
		`<notBefore>2026-01-01T00:00:00Z</notBefore>`,
		`<notAfter>2027-01-01T00:00:00Z</notAfter>`,
		`<expirationMilliseconds>900</expirationMilliseconds>`,
	} {
		require.Contains(t, xmlText, field)
	}
}

func TestNDNdStatusPageXMLIncludesXSLTPolyfill(t *testing.T) {
	encoded, err := encodeNdndStatusPageXML(&ndndStatusReport{})
	require.NoError(t, err)
	require.Contains(t, string(encoded), `<?xml-stylesheet type="text/xsl" href="ndnd-status.xsl"?>`)

	var page struct {
		Script struct {
			XMLName xml.Name
			Src     string `xml:"src,attr"`
		} `xml:"script"`
	}
	require.NoError(t, xml.Unmarshal(encoded, &page))
	require.Equal(t, "http://www.w3.org/1999/xhtml", page.Script.XMLName.Space)
	require.Equal(t, "ndnd-status-polyfill.min.js", page.Script.Src)
}

func TestNDNdContentStoreMissingPayload(t *testing.T) {
	report, err := ndndContentStoreFromStatus(&mgmt.CsInfoMsg{})
	require.ErrorContains(t, err, "no CsInfo payload")
	require.Equal(t, ndndContentStore{}, report)
}

func TestNDNdStatusRejectsUnsupportedWireVersions(t *testing.T) {
	_, err := ndndBIFTFromStatus(&mgmt.BiftStatusMsg{Version: mgmt.BiftStatusVersion + 1})
	require.ErrorContains(t, err, "unsupported BIFT status version")
	_, err = ndndDVPrefixEntriesFromStatus(&specDV.PrefixStateStatus{Version: specDV.PrefixStateStatusVersion + 1})
	require.ErrorContains(t, err, "unsupported DV prefix-state version")
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

func TestNDNdBIFTTLVMapping(t *testing.T) {
	routerName, err := enc.NameFromStr("/ndn/router")
	require.NoError(t, err)

	status := &mgmt.BiftStatusMsg{
		Version:   mgmt.BiftStatusVersion,
		BierIndex: optional.Some(uint64(7)),
		Entries: []*mgmt.BiftStatusEntry{{
			RouterName: routerName,
			BfrId:      3,
			NextHops:   []uint64{12},
			FbmBits:    []uint64{1, 4},
		}},
		Neighbors: []*mgmt.BiftStatusNeighbor{{FaceId: 12, FbmBits: []uint64{1, 4}}},
	}

	decoded, err := mgmt.ParseBiftStatusMsg(enc.NewWireView(status.Encode()), true)
	require.NoError(t, err)
	report, err := ndndBIFTFromStatus(decoded)
	require.NoError(t, err)
	require.Equal(t, uint64(7), *report.BierIndex)
	require.Equal(t, uint64(3), report.Entries[0].BFRID)
	require.Equal(t, "/ndn/router", report.Entries[0].RouterName)
	require.Equal(t, []uint64{1, 4}, report.Neighbors[0].FBMBits)

	disabled, err := ndndBIFTFromStatus(&mgmt.BiftStatusMsg{Version: mgmt.BiftStatusVersion})
	require.NoError(t, err)
	require.Nil(t, disabled.BierIndex)
}

func TestNDNdDVPrefixTLVToXML(t *testing.T) {
	prefix, err := enc.NameFromStr("/example/prefix")
	require.NoError(t, err)
	router, err := enc.NameFromStr("/example/router")
	require.NoError(t, err)

	status := &specDV.PrefixStateStatus{
		Version: specDV.PrefixStateStatusVersion,
		Entries: []*specDV.PrefixStateStatusEntry{{
			Name:           prefix,
			Router:         router,
			Multicast:      true,
			ValidityPeriod: &spec_2022.ValidityPeriod{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"},
			NextHops:       []*specDV.PrefixStateNextHop{{Face: 8, Cost: 3}},
		}},
	}
	decoded, err := specDV.ParsePrefixStateStatus(enc.NewWireView(status.Encode()), false)
	require.NoError(t, err)
	prefixes, err := ndndDVPrefixEntriesFromStatus(decoded)
	require.NoError(t, err)

	encoded, err := encodeNdndStatusXML(&ndndStatusReport{
		DVState: "available",
		DV: &ndndDVStatus{
			PrefixListState: "available",
			Prefixes:        prefixes,
		},
	})
	require.NoError(t, err)
	var report ndndStatusReport
	require.NoError(t, xml.Unmarshal(encoded, &report))
	require.Len(t, report.DV.Prefixes, 1)
	entry := report.DV.Prefixes[0]
	require.Equal(t, "/example/prefix", entry.Prefix)
	require.Equal(t, "/example/router", entry.Router)
	require.True(t, entry.Multicast)
	require.Equal(t, "2027-01-01T00:00:00Z", entry.Validity.NotAfter)
	require.Equal(t, uint64(8), entry.NextHops[0].FaceID)
	require.Equal(t, uint64(3), entry.NextHops[0].Cost)
}

func TestNDNdReportIncludesDVStatusAndPrefixDataset(t *testing.T) {
	network, err := enc.NameFromStr("/ndn")
	require.NoError(t, err)
	router, err := enc.NameFromStr("/ndn/router-a")
	require.NoError(t, err)
	prefix, err := enc.NameFromStr("/ndn/example")
	require.NoError(t, err)

	dvStatus := (&specDV.Status{
		Version:     "dv-test-version",
		NetworkName: &specDV.Destination{Name: network},
		RouterName:  &specDV.Destination{Name: router},
		NRibEntries: 2,
		NNeighbors:  1,
		NFibEntries: 3,
		NPsdEntries: 4,
	}).Encode()
	prefixStatus := (&specDV.PrefixStateStatus{
		Version: specDV.PrefixStateStatusVersion,
		Entries: []*specDV.PrefixStateStatusEntry{{
			Name:      prefix,
			Router:    router,
			Multicast: true,
			NextHops:  []*specDV.PrefixStateNextHop{{Face: 5, Cost: 7}},
		}},
	}).Encode()

	tool := &Tool{engine: &statusResponseEngine{
		timer: basic_engine.NewDummyTimer(),
		responses: map[string]enc.Wire{
			"/localhost/dv/status":      dvStatus,
			"/localhost/dv/prefix/list": prefixStatus,
		},
	}}
	status, err := tool.fetchDVStatus()
	require.NoError(t, err)
	report := &ndndStatusReport{DVState: "available", DV: status}
	require.NoError(t, tool.populateDVPrefixState(status))

	encoded, err := encodeNdndStatusXML(report)
	require.NoError(t, err)
	var decoded ndndStatusReport
	require.NoError(t, xml.Unmarshal(encoded, &decoded))
	require.Equal(t, "available", decoded.DVState)
	require.Equal(t, "/ndn", decoded.DV.NetworkName)
	require.Equal(t, "/ndn/router-a", decoded.DV.RouterName)
	require.Equal(t, uint64(1), decoded.DV.Neighbors)
	require.Equal(t, uint64(4), decoded.DV.PSDEntries)
	require.Equal(t, "available", decoded.DV.PrefixListState)
	require.Equal(t, "/ndn/example", decoded.DV.Prefixes[0].Prefix)
	require.True(t, decoded.DV.Prefixes[0].Multicast)
	require.Equal(t, uint64(5), decoded.DV.Prefixes[0].NextHops[0].FaceID)
	require.Equal(t, uint64(7), decoded.DV.Prefixes[0].NextHops[0].Cost)
}
