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

	"github.com/spf13/cobra"
)

//go:embed ndnd-status.html
var ndndStatusHTMLSource string

var ndndStatusHTML = template.Must(template.New("ndnd-status").Funcs(template.FuncMap{
	"optionalUint": func(value *uint64) string {
		if value == nil {
			return ""
		}
		return fmt.Sprint(*value)
	},
}).Parse(ndndStatusHTMLSource))

func (t *Tool) RunStatusServer(_ *cobra.Command, _ []string) error {
	t.Start()
	defer t.Stop()

	mux := statusServerHandler(t.buildNdndStatusReport)

	server := &http.Server{Addr: ":6380", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("NDNd status server failed: %w", err)
	}
	return nil
}

func statusServerHandler(buildReport func() (*ndndStatusReport, error)) http.Handler {
	var reportMu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != "/" && r.URL.Path != "/status.xml") || r.Method != http.MethodGet {
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
			http.Error(w, "NDNd status is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		var encoded []byte
		contentType := "text/html; charset=utf-8"
		if r.URL.Path == "/status.xml" {
			contentType = "application/xml; charset=utf-8"
			encoded, err = encodeNdndStatusXML(report)
		} else {
			encoded, err = renderNDNdStatusHTML(report)
		}
		if err != nil {
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
