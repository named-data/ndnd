package nfdc

import (
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

//go:embed ndnd-status.xsl
var ndndStatusXSL []byte

//go:embed ndnd-status-polyfill.min.js
var ndndStatusPolyfill []byte

func (t *Tool) RunStatusServer(_ *cobra.Command, _ []string) error {
	t.Start()
	defer t.Stop()

	var reportMu sync.Mutex
	mux := t.statusServerHandler(&reportMu)

	server := &http.Server{Addr: ":6380", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("NDNd status server failed: %w", err)
	}
	return nil
}

func (t *Tool) statusServerHandler(reportMu *sync.Mutex) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ndnd-status.xsl", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/xslt+xml; charset=utf-8")
		_, _ = w.Write(ndndStatusXSL)
	})
	mux.HandleFunc("/ndnd-status-polyfill.min.js", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprint(len(ndndStatusPolyfill)))
		_, _ = w.Write(ndndStatusPolyfill)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}

		reportMu.Lock()
		report, err := t.buildNdndStatusReport()
		reportMu.Unlock()
		if err != nil {
			http.Error(w, "NDNd status is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		encoded, err := encodeNdndStatusPageXML(report)
		if err != nil {
			http.Error(w, "NDNd status is temporarily unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
		_, _ = w.Write(encoded)
	})
	return mux
}
