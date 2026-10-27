package repo

import (
	"os"
	"path/filepath"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/trust_schema"
	"github.com/stretchr/testify/require"
)

func managementName(t *testing.T, value string) enc.Name {
	t.Helper()
	name, err := enc.NameFromStr(value)
	require.NoError(t, err)
	return name
}

func TestManagementSchemaOptional(t *testing.T) {
	schema, err := (&Config{}).managementSchema()
	require.NoError(t, err)
	require.IsType(t, trust_schema.NewNullSchema(), schema)
}

func TestManagementSchemaInvalid(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		wire []byte
		err  string
	}{
		{"unreadable", filepath.Join(t.TempDir(), "missing.tlv"), nil, "read management trust schema"},
		{"empty", filepath.Join(t.TempDir(), "empty.tlv"), []byte{}, "invalid management trust schema"},
		{"invalid", filepath.Join(t.TempDir(), "invalid.tlv"), []byte("invalid schema"), "invalid management trust schema"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.wire != nil {
				require.NoError(t, os.WriteFile(test.path, test.wire, 0600))
			}
			config := &Config{TrustSchema: test.path, StorageDir: t.TempDir()}
			r := NewRepo(config)
			require.ErrorContains(t, r.Start(), test.err)
			require.Nil(t, r.engine)
			require.Nil(t, r.store)
		})
	}
}
