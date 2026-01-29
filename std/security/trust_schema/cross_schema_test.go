package trust_schema_test

import (
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/security/trust_schema"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): TestSignCrossSchema verifies that a cross‑schema Data packet can be signed with a given signer, including a validity window, and that the resulting packet’s name, content, and signature validity periods can be correctly parsed and validated.
func TestSignCrossSchema(t *testing.T) {
	tu.SetT(t)

	aliceName, _ := enc.NameFromStr("/alice/KEY")
	signer, err := sig.KeygenEd25519(aliceName)
	require.NoError(t, err)

	T1 := time.Now()
	T2 := T1.Add(time.Hour)

	// Sign a cross schema
	name, _ := enc.NameFromStr("/app/32=INVITE/bob/v=1")
	cs := trust_schema.CrossSchemaContent{
		PrefixSchemaRules: []*trust_schema.PrefixSchemaRule{{
			NamePrefix: aliceName,
		}},
	}

	schema, err := trust_schema.SignCrossSchema(trust_schema.SignCrossSchemaArgs{
		Name:      name,
		Signer:    signer,
		Content:   cs,
		NotBefore: T1,
		NotAfter:  T2,
	})
	require.NoError(t, err)
	require.NotNil(t, schema)
	require.Greater(t, len(schema.Join()), 0)

	// Parse the schema
	parsed, _, err := spec_2022.Spec{}.ReadData(enc.NewWireView(schema))
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Make sure a segment component is appended to the name
	require.Equal(t, name.Append(enc.NewSegmentComponent(0)), parsed.Name())

	require.Equal(t, cs.Encode().Join(), parsed.Content().Join())
	nb, na := parsed.Signature().Validity()
	require.Equal(t, T1.Unix(), nb.Unwrap().Unix())
	require.Equal(t, T2.Unix(), na.Unwrap().Unix())
}

func TestCrossSchemaComponentRuleMatch(t *testing.T) {
	tu.SetT(t)

	dataName := tu.NoErr(enc.NameFromStr("/app/invite/team/alice/data"))
	dataPattern := tu.NoErr(enc.NameFromStr("/app/_/team")) // wildcard in the middle
	certName := tu.NoErr(enc.NameFromStr("/users/alice/KEY/kid/iss/ver"))

	cross := trust_schema.CrossSchemaContent{
		ComponentSchemaRules: []*trust_schema.ComponentSchemaRule{{
			NamePrefix:         dataPattern,
			KeyLocator:         &spec_2022.KeyLocator{Name: tu.NoErr(enc.NameFromStr("/users/_"))}, // wildcard in cert prefix
			NameComponentIndex: 3,                                                                  // capture "alice" in full data name
			KeyComponentIndex:  1,                                                                  // expect it immediately after "/users" in cert name
		}},
	}

	require.True(t, cross.Match(dataName, certName))

	mismatchCert := tu.NoErr(enc.NameFromStr("/users/bob/KEY/kid/iss/ver"))
	require.False(t, cross.Match(dataName, mismatchCert))

	shortName := tu.NoErr(enc.NameFromStr("/app/invite/team"))
	require.False(t, cross.Match(shortName, certName))
}
