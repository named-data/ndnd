package nfdc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatusServerServesEmbeddedPolyfill(t *testing.T) {
	handler := (&Tool{}).statusServerHandler(&sync.Mutex{})
	request := httptest.NewRequest(http.MethodGet, "/ndnd-status-polyfill.min.js", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, strings.HasPrefix(response.Header().Get("Content-Type"), "application/javascript"))
	require.Equal(t, ndndStatusPolyfill, response.Body.Bytes())
}
