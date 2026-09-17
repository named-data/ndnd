package merkle

import (
	"fmt"
	"os"
	"path/filepath"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/trust_schema"
)

// Config contains the configuration for a Merkle history log service.
type Config struct {
	// Name is the service prefix.
	Name string `json:"name"`
	// StorageDir contains the packet cache and persistent Merkle log.
	StorageDir string `json:"storage_dir"`
	// KeyChainUri specifies the keychain location.
	KeyChainUri string `json:"keychain"`
	// TrustSchema is the path to a compiled LVS trust schema.
	TrustSchema string `json:"trust_schema"`
	// TrustAnchors lists the full names of validation trust anchors.
	TrustAnchors []string `json:"trust_anchors"`

	nameN        enc.Name
	trustSchema  *trust_schema.LvsSchema
	trustAnchors []enc.Name
}

// Parse validates the configuration and prepares its storage directory.
func (c *Config) Parse() error {
	name, err := enc.NameFromStr(c.Name)
	if err != nil {
		return fmt.Errorf("failed to parse Merkle log name (%s): %w", c.Name, err)
	}
	if len(name) == 0 {
		return fmt.Errorf("merkle log name must not be empty")
	}
	if c.StorageDir == "" {
		return fmt.Errorf("storage-dir must be set")
	}
	if c.KeyChainUri == "" {
		return fmt.Errorf("keychain must be set")
	}
	if c.TrustSchema == "" {
		return fmt.Errorf("trust-schema must be set")
	}
	if len(c.TrustAnchors) == 0 {
		return fmt.Errorf("no trust anchors provided")
	}

	anchors := make([]enc.Name, len(c.TrustAnchors))
	for i, anchor := range c.TrustAnchors {
		anchors[i], err = enc.NameFromStr(anchor)
		if err != nil {
			return fmt.Errorf("failed to parse trust anchor name (%s): %w", anchor, err)
		}
		if len(anchors[i]) == 0 {
			return fmt.Errorf("trust anchor name must not be empty")
		}
	}

	trustSchemaPath, err := filepath.Abs(c.TrustSchema)
	if err != nil {
		return fmt.Errorf("failed to get absolute trust schema path: %w", err)
	}
	trustSchemaWire, err := os.ReadFile(trustSchemaPath)
	if err != nil {
		return fmt.Errorf("failed to read trust schema: %w", err)
	}
	schema, err := trust_schema.NewLvsSchema(trustSchemaWire)
	if err != nil {
		return fmt.Errorf("failed to parse trust schema: %w", err)
	}

	storageDir, err := filepath.Abs(c.StorageDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute storage path: %w", err)
	}
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	c.nameN = name
	c.StorageDir = storageDir
	c.TrustSchema = trustSchemaPath
	c.trustSchema = schema
	c.trustAnchors = anchors
	return nil
}

// DefaultConfig returns a configuration whose required fields are unset.
func DefaultConfig() *Config {
	return &Config{}
}
