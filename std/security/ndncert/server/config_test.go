package server

import (
	"os"
	"path/filepath"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigCPP(t *testing.T) {
	tu.SetT(t)

	raw := `{
  "ca-prefix": "/example",
  "ca-info": "An example NDNCERT CA",
  "max-validity-period": "1296000",
	"max-suffix-length": "5",
	"probe-parameters": [{"probe-parameter-key": "email"}],
	"name-assignment": {"email": "/edu/ucla"},
	"supported-challenges": [{"challenge": "pin"}, {"challenge": "email"}],
	"email": {
		"smtp-server": "smtp.example.org",
		"smtp-port": 587,
		"smtp-username": "ndncert",
		"smtp-password-env": "NDNCERT_SMTP_PASSWORD",
		"from": "NDN Certificate Robot <noreply@example.org>",
		"subject": "Your NDNCERT verification code"
	}
}`

	dir := t.TempDir()
	path := filepath.Join(dir, "ca.conf")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0644))

	cfg := tu.NoErr(LoadConfig(path))
	require.Equal(t, "/example", cfg.CaPrefix)
	require.Equal(t, "An example NDNCERT CA", cfg.CaInfo)
	require.Equal(t, "1296000", cfg.MaxValidityPeriod)
	require.Equal(t, "5", cfg.MaxSuffixLength)
	require.Equal(t, []ProbeParameterConfig{{Key: "email"}}, cfg.ProbeParameters)
	require.Equal(t, "/edu/ucla", cfg.NameAssignment["email"])
	require.Equal(t, 2, len(cfg.SupportedChallenges))
	require.True(t, cfg.SupportsChallenge("pin"))
	require.True(t, cfg.SupportsChallenge("email"))
	require.Equal(t, "smtp.example.org", cfg.Email.SMTPServer)
	require.False(t, cfg.SupportsChallenge("dns"))

	maxVal := tu.NoErr(cfg.GetMaxValidityPeriodSeconds())
	require.Equal(t, uint64(1296000), maxVal)
	profile, err := cfg.ToCaProfile(nil)
	require.NoError(t, err)
	require.Equal(t, []string{"email"}, profile.ParamKey)
	require.True(t, profile.MaxSuffixLength.IsSet())
	require.Equal(t, uint64(5), profile.MaxSuffixLength.Unwrap())
	parsed, err := tlv.ParseCaProfile(enc.NewWireView(profile.Encode()), false)
	require.NoError(t, err)
	require.Equal(t, profile.ParamKey, parsed.ParamKey)
	require.Equal(t, uint64(5), parsed.MaxSuffixLength.Unwrap())
}

func TestEmailNameAssignmentCPP(t *testing.T) {
	name, ok := assignEmailName("/edu/ucla", []byte("das@math.ucla.edu"))
	require.True(t, ok)
	want, err := enc.NameFromStr("/math/das")
	require.NoError(t, err)
	require.True(t, name.Equal(want))

	name, ok = assignEmailName("/edu/ucla", []byte("d/~.^as@6666=.9!"))
	require.True(t, ok)
	want, err = enc.NameFromStr("/9!/6666%3D/d%2F~.%5Eas")
	require.NoError(t, err)
	require.Equal(t, want, name)

	_, ok = assignEmailName("/nonexist", []byte("invalid-email"))
	require.False(t, ok)
}

func TestEmailRedirectDomainMatchCPP(t *testing.T) {
	require.True(t, emailDomainMatches("das@cs.ucla.edu", "cs.ucla.edu"))
	require.False(t, emailDomainMatches("das@math.ucla.edu", "cs.ucla.edu"))
	require.False(t, emailDomainMatches("das@CS.UCLA.EDU", "cs.ucla.edu"))
	require.False(t, emailDomainMatches("invalid-email", "cs.ucla.edu"))
}

func TestLoadConfigSample(t *testing.T) {
	tu.SetT(t)

	path := filepath.Join("..", "..", "..", "examples", "ndncert", "ca.conf.sample")
	cfg := tu.NoErr(LoadConfig(path))
	require.NotEmpty(t, cfg.CaPrefix)
	require.NotEmpty(t, cfg.MaxValidityPeriod)
	require.NotEmpty(t, cfg.SupportedChallenges)
}
