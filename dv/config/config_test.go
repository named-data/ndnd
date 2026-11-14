package config

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/trust_schema"
)

func TestRouterName(t *testing.T) {
	tests := []struct {
		name    string
		router  string
		wantErr bool
	}{
		{name: "direct child", router: "/ndnd/ucla"},
		{name: "nested", router: "/ndnd/edu/ucla/%C1.Router/suns"},
		{name: "network itself", router: "/ndnd", wantErr: true},
		{name: "too deep", router: "/ndnd/a/b/c/d/e", wantErr: true},
		{name: "outside network", router: "/other/ucla", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig()
			config.Network = "/ndnd"
			config.Router = test.router
			err := config.Parse()
			if (err != nil) != test.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestBundledSchemaAcceptsNestedRouter(t *testing.T) {
	schema, err := trust_schema.NewLvsSchema(SchemaBytes)
	if err != nil {
		t.Fatalf("NewLvsSchema() error = %v", err)
	}

	data := parseTestName(t, "/ndnd/edu/ucla/%C1.Router/suns/32=DV/32=STATUS")
	key := parseTestName(t, "/ndnd/edu/ucla/%C1.Router/suns/32=DV/KEY/router/root/v=1")
	if !schema.Check(data, key) {
		t.Fatal("bundled schema rejected nested router status data")
	}
}

func parseTestName(t *testing.T, value string) enc.Name {
	t.Helper()
	name, err := enc.NameFromStr(value)
	if err != nil {
		t.Fatalf("NameFromStr(%q) error = %v", value, err)
	}
	return name
}
