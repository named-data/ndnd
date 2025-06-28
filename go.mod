module github.com/named-data/ndnd

go 1.23.0

require (
	github.com/cespare/xxhash v1.1.0
	github.com/dgraph-io/badger/v4 v4.7.0
	github.com/goccy/go-yaml v1.17.1
	github.com/gorilla/websocket v1.5.3
	github.com/mattn/go-sqlite3 v1.14.28
	github.com/quic-go/quic-go v0.51.0
	github.com/quic-go/webtransport-go v0.8.0
	github.com/spf13/cobra v1.9.1
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.37.0
	golang.org/x/exp v0.0.0-20250408133849-7e4ce0ab07d0
	golang.org/x/sys v0.32.0
	golang.org/x/tools v0.32.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/google/pprof v0.0.0-20250423184734-337e5dd93bb4 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/onsi/ginkgo/v2 v2.23.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/mock v0.5.1 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/quic-go/webtransport-go v0.8.0 => github.com/zjkmxy/webtransport-go-patch v0.8.1
