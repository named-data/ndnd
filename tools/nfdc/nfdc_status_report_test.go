package nfdc

import (
	"testing"

	dvtlv "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/stretchr/testify/require"
)

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
