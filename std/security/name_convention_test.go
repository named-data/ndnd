package security_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	sec "github.com/named-data/ndnd/std/security"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Generates a key name from an identity name and verifies that the key name has the expected "/KEY" prefix and can be parsed back to the original identity.
func TestKeyName(t *testing.T) {
	tu.SetT(t)

	id, _ := enc.NameFromStr("/my/test/identity")
	keyPfx, _ := enc.NameFromStr("/my/test/identity/KEY")

	keyName := sec.MakeKeyName(id)
	require.True(t, keyPfx.IsPrefix(keyName))
	require.Equal(t, len(keyPfx)+1, len(keyName))

	id2, _ := sec.GetIdentityFromKeyName(keyName)
	require.Equal(t, id, id2)
}

// (AI GENERATED DESCRIPTION): Extracts the identity component from a key name, verifying it matches the expected `…/identity/KEY/<kid>` pattern and returns an error otherwise.
func TestGetIdentityFromKeyName(t *testing.T) {
	tu.SetT(t)

	name, err := sec.GetIdentityFromKeyName(tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid")))
	require.NoError(t, err)
	require.Equal(t, tu.NoErr(enc.NameFromStr("/my/test/identity")), name)

	_, err = sec.GetIdentityFromKeyName(tu.NoErr(enc.NameFromStr("/some/components")))
	require.Error(t, err)

	_, err = sec.GetIdentityFromKeyName(tu.NoErr(enc.NameFromStr("/wrong/components/KEY/wrong/this")))
	require.Error(t, err)

	_, err = sec.GetIdentityFromKeyName(enc.Name{})
	require.Error(t, err)
}

// (AI GENERATED DESCRIPTION): Creates a certificate name by appending the specified algorithm component and version number to a valid key name, returning an error if the key name is not properly formatted as a KEY name.
func TestMakeCertName(t *testing.T) {
	tu.SetT(t)

	keyName := tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid"))
	certName, err := sec.MakeCertName(keyName, enc.NewGenericComponent("Test"), 123)
	require.NoError(t, err)
	require.Equal(t, "/my/test/identity/KEY/kid/Test/v=123", certName.String())

	// invalid key name
	_, err = sec.MakeCertName(tu.NoErr(enc.NameFromStr("/my/test/identity")), // no KEY
		enc.NewGenericComponent("Test"), 123)
	require.Error(t, err)
}

// (AI GENERATED DESCRIPTION): Extracts the key name from a certificate name, verifying that the name follows the expected identity/KEY/kid structure and returns an error if it is malformed.
func TestGetKeyNameFromCertName(t *testing.T) {
	tu.SetT(t)

	certName := tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid/Test/v=123"))
	keyName, err := sec.GetKeyNameFromCertName(certName)
	require.NoError(t, err)
	require.Equal(t, tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid")), keyName)

	// implicit digest
	certName = tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid/Test/v=123/1=implicit"))
	keyName, err = sec.GetKeyNameFromCertName(certName)
	require.NoError(t, err)
	require.Equal(t, tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid")), keyName)

	// invalid cert names
	_, err = sec.GetKeyNameFromCertName(tu.NoErr(enc.NameFromStr("/my/test/identity/NOTKEY/kid/Test/v=123")))
	require.Error(t, err)

	_, err = sec.GetKeyNameFromCertName(tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid/Test/v=123/but/extra")))
	require.Error(t, err)

	_, err = sec.GetKeyNameFromCertName(enc.Name{})
	require.Error(t, err)
}

func TestCertListNaming(t *testing.T) {
	tu.SetT(t)

	keyName := tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid"))
	prefix, err := sec.CertListPrefix(keyName)
	require.NoError(t, err)
	require.True(t, prefix.At(-1).IsKeyword("auth"))

	// Exact prefix and version
	require.True(t, sec.CertListNameMatches(keyName, prefix))
	withVer := prefix.Append(enc.NewVersionComponent(1))
	require.True(t, sec.CertListNameMatches(keyName, withVer))
	// implicit digest stripped
	withDigest := withVer.Append(enc.Component{Typ: enc.TypeImplicitSha256DigestComponent})
	require.True(t, sec.CertListNameMatches(keyName, withDigest))

	// Wrong auth type (generic, not keyword)
	wrongAuth := keyName.Append(enc.NewGenericComponent("auth"))
	require.False(t, sec.CertListNameMatches(keyName, wrongAuth))
	// Extra components or wrong key
	require.False(t, sec.CertListNameMatches(keyName, withVer.Append(enc.NewSegmentComponent(0))))
	require.False(t, sec.CertListNameMatches(tu.NoErr(enc.NameFromStr("/other/KEY/kid")), withVer))

	// Version parsing
	require.Equal(t, uint64(1), sec.CertListVersion(withVer))
	require.Equal(t, uint64(1), sec.CertListVersion(withDigest))
	require.Equal(t, uint64(0), sec.CertListVersion(prefix))
}

func TestAnchorKeyNameFromLocator(t *testing.T) {
	tu.SetT(t)

	keyName := tu.NoErr(enc.NameFromStr("/my/test/identity/KEY/kid"))
	certName := keyName.Append(enc.NewGenericComponent("issuer"), enc.NewVersionComponent(5))
	issuerOnly := keyName.Append(enc.NewGenericComponent("issuer"))

	got, err := sec.KeyNameFromLocator(keyName)
	require.NoError(t, err)
	require.Equal(t, keyName, got)

	got, err = sec.KeyNameFromLocator(certName)
	require.NoError(t, err)
	require.Equal(t, keyName, got)

	got, err = sec.KeyNameFromLocator(issuerOnly)
	require.NoError(t, err)
	require.Equal(t, keyName, got)

	_, err = sec.KeyNameFromLocator(tu.NoErr(enc.NameFromStr("/wrong/components")))
	require.Error(t, err)
}
