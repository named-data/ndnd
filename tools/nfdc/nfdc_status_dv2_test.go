package nfdc

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/require"
)

type dv2DatasetTestEngine struct {
	ndn.Engine
	store ndn.Store
	queue chan func()
}

func (e *dv2DatasetTestEngine) Post(fn func()) { e.queue <- fn }

func (e *dv2DatasetTestEngine) Express(packet *ndn.EncodedInterest, callback ndn.ExpressCallbackFunc) error {
	interest, _, err := e.Spec().ReadInterest(enc.NewWireView(packet.Wire))
	if err != nil {
		return err
	}
	e.Post(func() {
		wire, err := e.store.Get(interest.Name(), interest.CanBePrefix())
		if err != nil || wire == nil {
			callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultError, Error: fmt.Errorf("test dataset unavailable")})
			return
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

func dv2DatasetTestTool(t *testing.T, datasets map[string]enc.Wire) *Tool {
	t.Helper()
	transport := &dv2DatasetTestEngine{Engine: engine.NewBasicEngine(face.NewDummyFace()), store: storage.NewMemoryStore(), queue: make(chan func(), 512)}
	for suffix, content := range datasets {
		_, err := object.Produce(ndn.ProduceArgs{Name: statusTrustName(t, "/localhost/nfd/"+suffix).WithVersion(1), Content: content, NoMetadata: true}, transport.store, nil)
		require.NoError(t, err)
	}
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
	t.Cleanup(func() { close(stop); <-stopped })
	return &Tool{engine: transport}
}

func TestDV2StatusDatasetsAndReports(t *testing.T) {
	large := ^uint64(0)
	pet := &mgmt.PetStatus{Entries: []*mgmt.PetEntry{{Name: statusTrustName(t, "/app/data"), Multicast: true,
		EgressRecords:  []*mgmt.EgressRecord{{Name: statusTrustName(t, "/example/a")}},
		NextHopRecords: []*mgmt.NextHopRecord{{FaceId: large, Cost: large}},
	}}}
	bift := &mgmt.BiftStatus{General: &mgmt.BiftGeneralStatus{BierIndex: optional.Some(uint64(0))},
		Entries:   []*mgmt.BiftEntry{{BfrId: 5, RouterName: statusTrustName(t, "/example/a"), NextHops: []uint64{large}, FbmBits: []uint64{0, 5}}},
		Neighbors: []*mgmt.BiftNeighbor{{FaceID: large, FbmBits: []uint64{0, 5}}},
	}
	fib := &mgmt.FibStatus{Entries: []*mgmt.FibEntry{{Name: pet.Entries[0].Name, NextHopRecords: pet.Entries[0].NextHopRecords}}}
	tool := dv2DatasetTestTool(t, map[string]enc.Wire{"fib/list": fib.Encode(), "pet/list": pet.Encode(), "bift/list": bift.Encode()})
	report := &ndndStatusReport{}
	require.NoError(t, tool.populateFIB(report))
	require.NoError(t, tool.populatePET(report))
	require.NoError(t, tool.populateBIFT(report))
	require.Equal(t, ndndPET{Entries: []ndndPETEntry{{Prefix: "/app/data", Multicast: true, EgressRouters: []string{"/example/a"}, NextHops: []ndndNextHop{{FaceID: large, Cost: large}}}}}, report.PET)
	require.Equal(t, report.PET.Entries[0].NextHops, report.FIB.Entries[0].NextHops)
	require.True(t, report.BIFT.Enabled)
	require.Equal(t, uint64(0), *report.BIFT.BierIndex)
	require.Equal(t, uint64(5), report.BIFT.Entries[0].BfrID)
	require.Equal(t, "/example/a", report.BIFT.Entries[0].Router)
	require.Equal(t, []ndndBIERNextHop{{FaceID: large}}, report.BIFT.Entries[0].NextHops)
	require.Equal(t, []uint64{0, 5}, report.BIFT.Neighbors[0].FbmBits)
	handler := statusServerHandler(func() (*ndndStatusReport, error) { return report, nil }, log.Default())
	for _, format := range []string{"xml", "json"} {
		t.Run(format, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status."+format, nil))
			require.Equal(t, http.StatusOK, response.Code)
			var parsed ndndStatusReport
			if format == "xml" {
				require.NoError(t, xml.Unmarshal(response.Body.Bytes(), &parsed))
			} else {
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &parsed))
				require.Equal(t, 4, strings.Count(response.Body.String(), `"faceId": "18446744073709551615"`))
				require.Contains(t, response.Body.String(), `"cost": "18446744073709551615"`)
			}
			require.Equal(t, report.PET, parsed.PET)
			require.Equal(t, report.BIFT, parsed.BIFT)
		})
	}
	page, err := renderNDNdStatusHTML(report)
	require.NoError(t, err)
	for _, text := range []string{"Prefix Egress Table (PET)", "/app/data", "BIER enabled; local bit index: 0", "Neighbor forwarding masks", "0, 5"} {
		require.Contains(t, string(page), text)
	}
}

func TestBIFTDisabled(t *testing.T) {
	tool := dv2DatasetTestTool(t, map[string]enc.Wire{"bift/list": (&mgmt.BiftStatus{General: &mgmt.BiftGeneralStatus{}}).Encode()})
	report := &ndndStatusReport{}
	require.NoError(t, tool.populateBIFT(report))
	require.False(t, report.BIFT.Enabled)
	require.Nil(t, report.BIFT.BierIndex)
	page, err := renderNDNdStatusHTML(report)
	require.NoError(t, err)
	require.Contains(t, string(page), "BIER disabled")
	require.NotContains(t, string(page), "local bit index:")
}

func TestBIFTRejectsInvalidPayloads(t *testing.T) {
	for _, content := range []enc.Wire{{[]byte(`{"bier_index":0}`)}, nil, (&mgmt.BiftStatus{Entries: []*mgmt.BiftEntry{{BfrId: 1}}}).Encode(), {[]byte{0xfd, 0x03, 0x00, 0x02, 0x00}}} {
		tool := dv2DatasetTestTool(t, map[string]enc.Wire{"bift/list": content})
		report := &ndndStatusReport{}
		require.Error(t, tool.populateBIFT(report))
		require.False(t, report.BIFT.Enabled)
	}
}

func TestDV2StatusSegmentedDatasets(t *testing.T) {
	pet := &mgmt.PetStatus{}
	bift := &mgmt.BiftStatus{General: &mgmt.BiftGeneralStatus{}}
	for i := range 1000 {
		name := statusTrustName(t, fmt.Sprintf("/example/router-%04d", i))
		pet.Entries = append(pet.Entries, &mgmt.PetEntry{Name: name, EgressRecords: []*mgmt.EgressRecord{{Name: name}}})
		bift.Entries = append(bift.Entries, &mgmt.BiftEntry{BfrId: uint64(i), RouterName: name, NextHops: []uint64{7}, FbmBits: []uint64{uint64(i)}})
	}
	require.Greater(t, pet.Encode().Length(), uint64(8000))
	require.Greater(t, bift.Encode().Length(), uint64(8000))
	tool := dv2DatasetTestTool(t, map[string]enc.Wire{"pet/list": pet.Encode(), "bift/list": bift.Encode()})
	report := &ndndStatusReport{}
	require.NoError(t, tool.populatePET(report))
	require.NoError(t, tool.populateBIFT(report))
	require.Len(t, report.PET.Entries, 1000)
	require.Len(t, report.BIFT.Entries, 1000)
	require.Equal(t, "/example/router-0999", report.PET.Entries[999].Prefix)
	require.Equal(t, uint64(999), report.BIFT.Entries[999].BfrID)
}
