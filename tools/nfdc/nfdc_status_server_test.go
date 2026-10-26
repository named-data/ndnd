package nfdc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStatusServerServesStylesheet(t *testing.T) {
	handler := statusServerHandler(nil)
	request := httptest.NewRequest(http.MethodGet, "/ndnd-status.xsl", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, strings.HasPrefix(response.Header().Get("Content-Type"), "application/xslt+xml"))
	require.Equal(t, ndndStatusXSL, response.Body.Bytes())
}

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
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.NotContains(t, response.Body.String(), "internal detail")
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
	response := httptest.NewRecorder()
	secondDone := make(chan struct{})
	go func() { handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil)); close(secondDone) }()
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent status request was queued")
	}
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	// Releasing the first request is deferred even if an assertion fails.
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("status request did not finish")
		}
	})
}
