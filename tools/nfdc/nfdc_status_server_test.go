package nfdc

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStatusServerServesPage(t *testing.T) {
	handler := statusServerHandler(func() (*ndndStatusReport, error) {
		return &ndndStatusReport{DV: ndndDVStatus{
			Available: true, DatasetAvailable: true,
			Routers: []ndndDVRouter{{Name: "/example/a", Prefixes: []ndndDVPrefix{{Name: "/app/data", Cost: 3}}}},
		}}, nil
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Header().Get("Content-Type"), "text/html")
	require.Contains(t, response.Body.String(), "/app/data (cost 3)")
}

func TestStatusServerDatasetFailure(t *testing.T) {
	handler := statusServerHandler(func() (*ndndStatusReport, error) { return nil, errors.New("internal detail") })
	for _, path := range []string{"/", "/status.xml", "/status.json"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, http.StatusServiceUnavailable, response.Code)
			require.NotContains(t, response.Body.String(), "internal detail")
		})
	}
}

func TestStatusServerServesMachineReadableReports(t *testing.T) {
	report := &ndndStatusReport{
		General: ndndGeneralStatus{Version: "test<&>version", NFIBEntries: 3},
		DV: ndndDVStatus{Available: true, DatasetAvailable: true,
			Routers: []ndndDVRouter{{Name: "/example/a", Prefixes: []ndndDVPrefix{{Name: "/app/data", Cost: 3}}}},
		},
	}
	for _, format := range []struct {
		name   string
		decode func([]byte, any) error
		encode func(*ndndStatusReport) ([]byte, error)
	}{
		{"xml", xml.Unmarshal, encodeNdndStatusXML},
		{"json", json.Unmarshal, encodeNdndStatusJSON},
	} {
		t.Run(format.name, func(t *testing.T) {
			calls := 0
			handler := statusServerHandler(func() (*ndndStatusReport, error) { calls++; return report, nil })
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status."+format.name, nil))
			require.Equal(t, http.StatusOK, response.Code)
			require.Equal(t, "application/"+format.name+"; charset=utf-8", response.Header().Get("Content-Type"))
			require.Equal(t, strconv.Itoa(response.Body.Len()), response.Header().Get("Content-Length"))
			require.Equal(t, 1, calls)
			expected, err := format.encode(report)
			require.NoError(t, err)
			require.Equal(t, expected, response.Body.Bytes())
			var parsed ndndStatusReport
			require.NoError(t, format.decode(response.Body.Bytes(), &parsed))
			require.Equal(t, report.General, parsed.General)
			require.Equal(t, report.DV, parsed.DV)
		})
	}
}

func TestStatusServerRejectsInvalidReportRequests(t *testing.T) {
	handler := statusServerHandler(nil)
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/status.xml", nil),
		httptest.NewRequest(http.MethodGet, "/status.xml/extra", nil),
		httptest.NewRequest(http.MethodPost, "/status.json", nil),
		httptest.NewRequest(http.MethodGet, "/status.json/extra", nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusNotFound, response.Code)
	}
}

func TestStatusServerCollectorPanicReleasesLock(t *testing.T) {
	calls := 0
	handler := statusServerHandler(func() (*ndndStatusReport, error) {
		calls++
		if calls == 1 {
			panic("collector failure")
		}
		return &ndndStatusReport{}, nil
	})
	// net/http recovers handler panics and continues serving requests.
	require.Panics(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, 2, calls)
}

func TestStatusServerRejectsConcurrentReports(t *testing.T) {
	started, release, done := make(chan struct{}, 2), make(chan struct{}), make(chan struct{})
	handler := statusServerHandler(func() (*ndndStatusReport, error) {
		started <- struct{}{}
		<-release
		return &ndndStatusReport{}, nil
	})
	defer close(release)
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first status request did not start")
	}
	for _, path := range []string{"/status.xml", "/status.json"} {
		response := httptest.NewRecorder()
		secondDone := make(chan struct{})
		go func() {
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			close(secondDone)
		}()
		select {
		case <-secondDone:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent status request was queued")
		}
		require.Equal(t, http.StatusServiceUnavailable, response.Code)
	}
	// Releasing the first request is deferred even if an assertion fails.
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("status request did not finish")
		}
	})
}
