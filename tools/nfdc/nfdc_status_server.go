package nfdc

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/named-data/ndnd/std/log"
	"github.com/spf13/cobra"
)

//go:embed ndnd-status.html
var ndndStatusHTMLSource string

var ndndStatusHTML = template.Must(template.New("ndnd-status").Funcs(template.FuncMap{
	"bitList": formatBitList,
	"optionalUint": func(value *uint64) string {
		if value == nil {
			return ""
		}
		return fmt.Sprint(*value)
	},
}).Parse(ndndStatusHTMLSource))

func (t *Tool) RunStatusServer(_ *cobra.Command, _ []string) error {
	if err := t.configureStatusTrust(); err != nil {
		return err
	}
	t.Start()
	defer t.Stop()

	mux := statusServerHandler(t.buildNdndStatusReport, log.Default())

	server := &http.Server{Addr: ":6380", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("NDNd status server failed: %w", err)
	}
	return nil
}

func statusServerHandler(buildReport func() (*ndndStatusReport, error), logger *log.Logger) http.Handler {
	var reportMu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		encode := renderNDNdStatusHTML
		contentType := "text/html; charset=utf-8"
		switch r.URL.Path {
		case "/":
		case "/status.xml":
			contentType = "application/xml; charset=utf-8"
			encode = encodeNdndStatusXML
		case "/status.json":
			contentType = "application/json; charset=utf-8"
			encode = encodeNdndStatusJSON
		default:
			http.NotFound(w, r)
			return
		}

		if !reportMu.TryLock() {
			http.Error(w, "NDNd status is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		report, err := func() (*ndndStatusReport, error) {
			defer reportMu.Unlock()
			return buildReport()
		}()
		if err != nil {
			logger.Error(nil, "Failed to collect NDNd status report", "path", r.URL.Path, "err", err)
			http.Error(w, "NDNd status is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		encoded, err := encode(report)
		if err != nil {
			logger.Error(nil, "Failed to encode NDNd status report", "path", r.URL.Path, "err", err)
			http.Error(w, "NDNd status is temporarily unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
		_, _ = w.Write(encoded)
	})
	return mux
}

func renderNDNdStatusHTML(report *ndndStatusReport) ([]byte, error) {
	var output bytes.Buffer
	if err := ndndStatusHTML.Execute(&output, report); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
