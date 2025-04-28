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

	// NameN is the parsed name of the repo service.
	NameN enc.Name
}

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

func DefaultConfig() *Config {
	return &Config{
		Name:       "", // invalid
		StorageDir: "", // invalid

		NameN: nil,
	}
}
