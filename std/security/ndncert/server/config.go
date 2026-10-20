package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	"github.com/named-data/ndnd/std/types/optional"
)

type ChallengeConfig struct {
	Name string `json:"challenge"`
}

type ProbeParameterConfig struct {
	Key string `json:"probe-parameter-key"`
}

type RedirectConfig struct {
	CaPrefix    string `json:"ca-prefix"`
	Certificate string `json:"certificate"`
	PolicyType  string `json:"policy-type"`
	PolicyParam string `json:"policy-param"`
}

type EmailChallengeConfig struct {
	SMTPServer      string `json:"smtp-server"`
	SMTPPort        int    `json:"smtp-port"`
	SMTPUsername    string `json:"smtp-username"`
	SMTPPasswordEnv string `json:"smtp-password-env"`
	From            string `json:"from"`
	Subject         string `json:"subject"`
}

type CaConfig struct {
	CaPrefix            string                 `json:"ca-prefix"`
	CaInfo              string                 `json:"ca-info"`
	MaxValidityPeriod   string                 `json:"max-validity-period"`
	MaxSuffixLength     string                 `json:"max-suffix-length"`
	ProbeParameters     []ProbeParameterConfig `json:"probe-parameters"`
	NameAssignment      map[string]string      `json:"name-assignment"`
	RedirectTo          []RedirectConfig       `json:"redirect-to"`
	SupportedChallenges []ChallengeConfig      `json:"supported-challenges"`
	Email               EmailChallengeConfig   `json:"email"`

	CaCertPath string `json:"-"`
	CaKeyPath  string `json:"-"`
}

func LoadConfig(path string) (*CaConfig, error) {
	// log.Printf("loading ca config: %s", path)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg CaConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config json: %w", err)
	}

	if cfg.CaPrefix == "" {
		return nil, fmt.Errorf("ca-prefix is required")
	}
	if cfg.MaxValidityPeriod == "" {
		return nil, fmt.Errorf("max-validity-period is required")
	}
	if cfg.MaxSuffixLength != "" {
		if _, err := strconv.ParseUint(cfg.MaxSuffixLength, 10, 64); err != nil {
			return nil, fmt.Errorf("invalid max-suffix-length: %w", err)
		}
	}
	for _, param := range cfg.ProbeParameters {
		if strings.TrimSpace(param.Key) == "" {
			return nil, fmt.Errorf("probe-parameter-key must not be empty")
		}
	}
	for _, redirect := range cfg.RedirectTo {
		if redirect.PolicyType != "email" {
			return nil, fmt.Errorf("unsupported redirect policy type %q", redirect.PolicyType)
		}
		if redirect.CaPrefix == "" || redirect.Certificate == "" || redirect.PolicyParam == "" {
			return nil, fmt.Errorf("redirect-to requires ca-prefix, certificate, and policy-param")
		}
		if _, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(redirect.Certificate), "")); err != nil {
			return nil, fmt.Errorf("invalid redirect certificate: %w", err)
		}
	}
	if cfg.SupportsChallenge(ndncert.KwEmail) {
		if err := cfg.Email.Validate(); err != nil {
			return nil, fmt.Errorf("invalid email challenge configuration: %w", err)
		}
	}

	return &cfg, nil
}

func (c EmailChallengeConfig) Validate() error {
	if strings.TrimSpace(c.SMTPServer) == "" || strings.ContainsAny(c.SMTPServer, " \t\r\n") {
		return fmt.Errorf("smtp-server is required and must be a hostname")
	}
	if c.SMTPPort < 0 || c.SMTPPort > 65535 {
		return fmt.Errorf("smtp-port must be 0 (default 587) or between 1 and 65535")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return fmt.Errorf("invalid from address: %w", err)
	}
	if strings.ContainsAny(c.Subject, "\r\n") {
		return fmt.Errorf("subject must not contain newlines")
	}
	if c.SMTPUsername != "" && c.SMTPPasswordEnv == "" {
		return fmt.Errorf("smtp-password-env is required when smtp-username is set")
	}
	return nil
}

func (c *CaConfig) ToCaProfile(caCertWire enc.Wire) (*tlv.CaProfile, error) {
	caName, err := enc.NameFromStr(c.CaPrefix)
	if err != nil {
		return nil, fmt.Errorf("invalid ca-prefix: %w", err)
	}

	mv, err := strconv.ParseUint(c.MaxValidityPeriod, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid max-validity-period: %w", err)
	}

	profile := &tlv.CaProfile{
		CaPrefix:       &spec.NameContainer{Name: caName},
		CaInfo:         c.CaInfo,
		ParamKey:       make([]string, 0, len(c.ProbeParameters)),
		MaxValidPeriod: mv,
		CaCert:         caCertWire,
	}
	for _, param := range c.ProbeParameters {
		profile.ParamKey = append(profile.ParamKey, param.Key)
	}
	if c.MaxSuffixLength != "" {
		maxSuffixLength, err := strconv.ParseUint(c.MaxSuffixLength, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid max-suffix-length: %w", err)
		}
		profile.MaxSuffixLength = optional.Some(maxSuffixLength)
	}
	return profile, nil
}

func (c *CaConfig) GetMaxValidityPeriodSeconds() (uint64, error) {
	return strconv.ParseUint(c.MaxValidityPeriod, 10, 64)
}

func (c *CaConfig) SupportsChallenge(name string) bool {
	for _, ch := range c.SupportedChallenges {
		if ch.Name == name {
			return true
		}
	}
	return false
}
