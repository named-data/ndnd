package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

type ProbeParam struct {
	Key string `json:"probe-parameter-key"`
}

type ChallengeConfig struct {
	Name string `json:"challenge"`
}

type RedirectConfig struct {
	CaPrefix    string `json:"ca-prefix"`
	Certificate string `json:"certificate"`
	PolicyType  string `json:"policy-type"`
	PolicyParam string `json:"policy-param"`
}

type CaConfig struct {
	CaPrefix           string            `json:"ca-prefix"`
	CaInfo             string            `json:"ca-info"`
	MaxValidityPeriod  string            `json:"max-validity-period"`
	MaxSuffixLength    string            `json:"max-suffix-length"`
	ProbeParameters    []ProbeParam      `json:"probe-parameters"`
	SupportedChallenges []ChallengeConfig `json:"supported-challenges"`
	RedirectTo         []RedirectConfig  `json:"redirect-to"`

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

	return &cfg, nil
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

	pkeys := make([]string, len(c.ProbeParameters))
	for i, p := range c.ProbeParameters {
		pkeys[i] = p.Key
	}

	return &tlv.CaProfile{
		CaPrefix:       &spec.NameContainer{Name: caName},
		CaInfo:         c.CaInfo,
		ParamKey:       pkeys,
		MaxValidPeriod: mv,
		CaCert:         caCertWire,
	}, nil
}

func (c *CaConfig) GetMaxValidityPeriodSeconds() (uint64, error) {
	return strconv.ParseUint(c.MaxValidityPeriod, 10, 64)
}

func (c *CaConfig) GetMaxSuffixLength() (uint64, error) {
	if c.MaxSuffixLength == "" {
		return 2, nil
	}
	return strconv.ParseUint(c.MaxSuffixLength, 10, 64)
}

func (c *CaConfig) SupportsChallenge(name string) bool {
	for _, ch := range c.SupportedChallenges {
		if ch.Name == name {
			return true
		}
	}
	return false
}

func (c *CaConfig) GetProbeParamKeys() []string {
	keys := make([]string, len(c.ProbeParameters))
	for i, p := range c.ProbeParameters {
		keys[i] = p.Key
	}
	return keys
}
