package nfdc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatusServerServesStylesheet(t *testing.T) {
	handler := (&Tool{}).statusServerHandler(&sync.Mutex{})
	request := httptest.NewRequest(http.MethodGet, "/ndnd-status.xsl", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, strings.HasPrefix(response.Header().Get("Content-Type"), "application/xslt+xml"))
	require.Equal(t, ndndStatusXSL, response.Body.Bytes())
}
