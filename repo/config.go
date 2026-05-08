package repo

import (
	"fmt"
	"os"
	"path/filepath"

	enc "github.com/named-data/ndnd/std/encoding"
)

type Config struct {
	// Name is the name of the repo service.
	Name string `json:"name"`
	// StorageDir is the directory to store data.
	StorageDir string `json:"storage_dir"`
	// URI specifying KeyChain location.
	KeyChainUri string `json:"keychain"`
	// List of trust anchor full names.
	TrustAnchors []string `json:"trust_anchors"`
	// IgnoreValidity skips validity period checks when fetching remote data (e.g. SVS snapshots).
	IgnoreValidity bool `json:"ignore_validity"`

	// NameN is the parsed name of the repo service.
	NameN enc.Name
}

// (AI GENERATED DESCRIPTION): Parses the configuration by validating the repository name, ensuring a storage directory is specified, converting it to an absolute path, and creating the directory if necessary.
func (c *Config) Parse() (err error) {
	c.NameN, err = enc.NameFromStr(c.Name)
	if err != nil || len(c.NameN) == 0 {
		return fmt.Errorf("failed to parse or invalid repo name (%s): %w", c.Name, err)
	}

	if c.StorageDir == "" {
		return fmt.Errorf("storage-dir must be set")
	} else {
		path, err := filepath.Abs(c.StorageDir)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create storage directory: %w", err)
		}
		c.StorageDir = path
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Returns the trust‑anchor names stored in the Config as parsed enc.Name objects, panicking if any string cannot be parsed.
func (c *Config) TrustAnchorNames() []enc.Name {
	res := make([]enc.Name, len(c.TrustAnchors))
	for i, ta := range c.TrustAnchors {
		var err error
		res[i], err = enc.NameFromStr(ta)
		if err != nil {
			panic(fmt.Sprintf("failed to parse trust anchor name (%s): %v", ta, err))
		}
	}
	return res
}

// (AI GENERATED DESCRIPTION): Returns a new Config with default placeholder values: empty Name and StorageDir strings, and a nil NameN slice.
func DefaultConfig() *Config {
	return &Config{
		Name:       "", // invalid
		StorageDir: "", // invalid

		NameN: nil,
	}
}
