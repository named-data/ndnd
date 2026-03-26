package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_CPPCompatibility(t *testing.T) {
	testConfig := `{
  "ca-prefix": "/example",
  "ca-info": "An example NDNCERT CA",
  "max-validity-period": "1296000",
  "max-suffix-length": "2",
  "probe-parameters": [
    {
      "probe-parameter-key": "email"
    }
  ],
  "supported-challenges": [
    {
      "challenge": "pin"
    },
    {
      "challenge": "email"
    }
  ]
}`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-ca.conf")
	err := os.WriteFile(configPath, []byte(testConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.CaPrefix != "/example" {
		t.Errorf("Expected ca-prefix '/example', got '%s'", config.CaPrefix)
	}

	if config.CaInfo != "An example NDNCERT CA" {
		t.Errorf("Expected ca-info 'An example NDNCERT CA', got '%s'", config.CaInfo)
	}

	if config.MaxValidityPeriod != "1296000" {
		t.Errorf("Expected max-validity-period '1296000', got '%s'", config.MaxValidityPeriod)
	}

	if len(config.ProbeParameters) != 1 {
		t.Errorf("Expected 1 probe parameter, got %d", len(config.ProbeParameters))
	}

	if len(config.SupportedChallenges) != 2 {
		t.Errorf("Expected 2 supported challenges, got %d", len(config.SupportedChallenges))
	}

	if !config.SupportsChallenge("pin") {
		t.Error("Expected to support 'pin' challenge")
	}

	if !config.SupportsChallenge("email") {
		t.Error("Expected to support 'email' challenge")
	}

	if config.SupportsChallenge("dns") {
		t.Error("Should not support 'dns' challenge")
	}

	maxValidity, err := config.GetMaxValidityPeriodSeconds()
	if err != nil {
		t.Fatalf("Failed to get max validity period: %v", err)
	}
	if maxValidity != 1296000 {
		t.Errorf("Expected max validity 1296000, got %d", maxValidity)
	}
}

func TestLoadConfig_SampleFile(t *testing.T) {
	configPath := filepath.Join("..", "..", "..", "examples", "ndncert", "ca.conf.sample")

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load sample config: %v", err)
	}

	if config.CaPrefix == "" {
		t.Fatalf("Expected ca-prefix to be set")
	}
	if config.MaxValidityPeriod == "" {
		t.Fatalf("Expected max-validity-period to be set")
	}
	if len(config.SupportedChallenges) == 0 {
		t.Fatalf("Expected at least one supported challenge")
	}
}
