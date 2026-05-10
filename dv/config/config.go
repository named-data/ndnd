package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// CostInfinity is the maximum cost to a router.
const CostInfinity = uint64(16)

// CostPfxInfinity is the maximum cost to a name prefix.
const CostPfxInfinity = uint64(0xFFFFFFFF)

// NlsrOrigin is the origin to use for local registration.
const NlsrOrigin = uint64(mgmt.RouteOriginNLSR)
const PrefixInsOrigin = uint64(mgmt.RouteOriginPrefixIns)

var MulticastStrategy = enc.LOCALHOST.
	Append(enc.NewGenericComponent("nfd")).
	Append(enc.NewGenericComponent("strategy")).
	Append(enc.NewGenericComponent("multicast"))

//go:embed schema.tlv
var SchemaBytes []byte

type Config struct {
	// Network should be the same for all routers in the network.
	Network string `json:"network"`
	// Router should be unique for each router in the network.
	Router string `json:"router"`
	// Period of sending Advertisement Sync Interests.
	AdvertisementSyncInterval_ms uint64 `json:"advertise_interval"`
	// Period of sending Prefix Sync Interests.
	PrefixSyncInterval_ms uint64 `json:"prefix_sync_interval"`
	// Time after which a neighbor is considered dead.
	RouterDeadInterval_ms uint64 `json:"router_dead_interval"`
	// URI specifying KeyChain location.
	KeyChainUri string `json:"keychain"`
	// List of trust anchor full names.
	TrustAnchors []string `json:"trust_anchors"`
	// Path to trust schema TLV file.
	// If omitted, NullSchema is used.
	TrustSchemaPath string `json:"trust_schema"`
	// URI specifying KeyChain location for prefix insertion verifier.
	PrefixInsertionKeychainUri string `json:"prefix_insertion_keychain"`
	// List of trust anchor full names for prefix insertion.
	PrefixInsertionTrustAnchors []string `json:"prefix_insertion_trust_anchors"`
	// Path to trust schema TLV file used for prefix insertion validation.
	// If omitted, NullSchema is used.
	PrefixInsertionTrustSchemaPath string `json:"prefix_insertion_trust_schema"`
	// List of permanent neighbors.
	Neighbors []Neighbor `json:"neighbors"`
	// Replicate Prefix State into forwarder PET.
	PrefixStateReplicate bool `json:"prefix_egre_state_replicate"`
	// Directory that contains the loaded config file.
	ConfigDir string `json:"-"`

	// Parsed Global Prefix
	networkNameN enc.Name
	// Parsed Router Prefix
	routerNameN enc.Name
	// Advertisement Sync Prefix
	advSyncPfxN enc.Name
	// Advertisement Sync Prefix (Active)
	advSyncActivePfxN enc.Name
	// Advertisement Sync Prefix (Passive)
	advSyncPassivePfxN enc.Name
	// Advertisement Data Prefix
	advDataPfxN enc.Name
	// Prefix Sync Prefix
	pfxSyncGroupPfxN enc.Name
	// Local management prefix
	mgmtPrefix enc.Name
	// Trust anchor names
	trustAnchorsN []enc.Name
	// Prefix Insertion trust anchor names
	prefixInsertionTrustAnchorsN []enc.Name
	// Loaded routing trust schema bytes.
	// Empty means NullSchema.
	trustSchema []byte
	// Loaded prefix insertion trust schema bytes.
	// Empty means NullSchema.
	prefixInsertionTrustSchema []byte
}

type Neighbor struct {
	// Remote URI of the neighbor.
	Uri string `json:"uri"`
	// MTU of the link face.
	Mtu uint64 `json:"mtu"`

	// FaceId of the neighbor.
	FaceId uint64 `json:"-"`
	// Whether this instance created this face
	Created bool `json:"-"`
}

// (AI GENERATED DESCRIPTION): Creates a default `Config` instance with empty network and router fields and preset advertisement sync and router‑dead intervals.
func DefaultConfig() *Config {
	return &Config{
		Network:                      "", // invalid
		Router:                       "", // invalid
		AdvertisementSyncInterval_ms: 5000,
		// Follow advertise_interval unless configured explicitly.
		PrefixSyncInterval_ms:          0,
		RouterDeadInterval_ms:          30000,
		KeyChainUri:                    "",
		PrefixInsertionKeychainUri:     "",
		TrustSchemaPath:                "",
		PrefixInsertionTrustSchemaPath: "",
		PrefixStateReplicate:       true,
	}
}

// (AI GENERATED DESCRIPTION): Parses and validates the NLSR configuration, converting string fields into `enc.Name` objects, enforcing network‑router relationship and timing constraints, and computing the internal name prefixes used for advertisement sync, data, and prefix sync.
func (c *Config) Parse() (err error) {
	// Validate prefixes not empty
	if c.Network == "" || c.Router == "" {
		return fmt.Errorf("network and router must be set")
	}

	// Parse prefixes
	c.networkNameN, err = enc.NameFromStr(c.Network)
	if err != nil {
		return err
	}

	c.routerNameN, err = enc.NameFromStr(c.Router)
	if err != nil {
		return err
	}

	// Max 3 components in network name due to the trust schema
	if len(c.networkNameN) > 3 {
		return fmt.Errorf("network name can have at most 3 components")
	}

	// Make sure router is in the network
	if !c.networkNameN.IsPrefix(c.routerNameN) {
		return fmt.Errorf("network name is required to be a prefix of router name")
	}

	// Make sure router length is exactly one more than network
	if len(c.routerNameN) != len(c.networkNameN)+1 {
		return fmt.Errorf("router name must be exactly one component longer than network name")
	}

	// Validate intervals are not too short
	if c.AdvertisementSyncInterval() < 1*time.Second {
		return fmt.Errorf("AdvertisementSyncInterval must be at least 1 second")
	}
	if c.PrefixSyncInterval_ms == 0 {
		c.PrefixSyncInterval_ms = c.AdvertisementSyncInterval_ms
	}
	if c.PrefixSyncInterval() < 1*time.Second {
		return fmt.Errorf("PrefixSyncInterval must be at least 1 second")
	}

	// Dead interval at least 2 sync intervals
	if c.RouterDeadInterval() < 2*c.AdvertisementSyncInterval() {
		return fmt.Errorf("RouterDeadInterval must be at least 2*AdvertisementSyncInterval")
	}

	// Validate trust anchors
	c.trustAnchorsN = make([]enc.Name, 0, len(c.TrustAnchors))
	for _, anchor := range c.TrustAnchors {
		name, err := enc.NameFromStr(anchor)
		if err != nil {
			return err
		}
		c.trustAnchorsN = append(c.trustAnchorsN, name)
	}

	c.prefixInsertionTrustAnchorsN = make([]enc.Name, 0, len(c.PrefixInsertionTrustAnchors))
	for _, anchor := range c.PrefixInsertionTrustAnchors {
		name, err := enc.NameFromStr(anchor)
		if err != nil {
			return err
		}
		c.prefixInsertionTrustAnchorsN = append(c.prefixInsertionTrustAnchorsN, name)
	}
	prefixInsertionKeychain := strings.TrimSpace(c.PrefixInsertionKeychainUri)
	if prefixInsertionKeychain == "" {
		prefixInsertionKeychain = strings.TrimSpace(c.KeyChainUri)
	}
	c.PrefixInsertionKeychainUri = prefixInsertionKeychain

	if len(c.prefixInsertionTrustAnchorsN) == 0 {
		c.prefixInsertionTrustAnchorsN = append(c.prefixInsertionTrustAnchorsN, c.trustAnchorsN...)
	}

	// Load routing trust schema bytes.
	trustSchemaPath := strings.TrimSpace(c.TrustSchemaPath)
	if trustSchemaPath == "" {
		c.trustSchema = nil
	} else {
		c.trustSchema, err = c.readConfigBytes(trustSchemaPath)
		if err != nil {
			return fmt.Errorf("failed to read trust schema: %w", err)
		}
	}

	// Load prefix insertion trust schema bytes.
	prefixSchemaPath := strings.TrimSpace(c.PrefixInsertionTrustSchemaPath)
	if prefixSchemaPath == "" {
		// If routing schema is configured from file, allow inheritance.
		if trustSchemaPath != "" {
			prefixSchemaPath = trustSchemaPath
		}
	}
	if prefixSchemaPath == "" {
		c.prefixInsertionTrustSchema = nil
	} else {
		c.prefixInsertionTrustSchema, err = c.readConfigBytes(prefixSchemaPath)
		if err != nil {
			return fmt.Errorf("failed to read prefix insertion trust schema: %w", err)
		}
	}

	// Advertisement sync and data prefixes
	c.advSyncPfxN = enc.LOCALHOP.
		Append(c.networkNameN...).
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("ADS"))
	c.advSyncActivePfxN = c.advSyncPfxN.
		Append(enc.NewKeywordComponent("ACT"))
	c.advSyncPassivePfxN = c.advSyncPfxN.
		Append(enc.NewKeywordComponent("PSV"))
	c.advDataPfxN = enc.LOCALHOP.
		Append(c.routerNameN...).
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("ADV"))

	// Prefix sync prefix
	c.pfxSyncGroupPfxN = c.networkNameN.
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("PSD"))

	// Local prefixes to NFD
	c.mgmtPrefix = enc.LOCALHOST.
		Append(enc.NewGenericComponent("dv"))

	return nil
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the network name stored in the configuration.
func (c *Config) NetworkName() enc.Name {
	return c.networkNameN
}

// (AI GENERATED DESCRIPTION): Returns the router name (enc.Name) stored in the Config instance.
func (c *Config) RouterName() enc.Name {
	return c.routerNameN
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the advertisement sync prefix stored in the configuration as an `enc.Name`.
func (c *Config) AdvertisementSyncPrefix() enc.Name {
	return c.advSyncPfxN
}

// (AI GENERATED DESCRIPTION): Retrieves the configured advertisement sync active prefix (an `enc.Name`) from the `Config` instance.
func (c *Config) AdvertisementSyncActivePrefix() enc.Name {
	return c.advSyncActivePfxN
}

// (AI GENERATED DESCRIPTION): Returns the Name of the prefix used for passive advertisement synchronization.
func (c *Config) AdvertisementSyncPassivePrefix() enc.Name {
	return c.advSyncPassivePfxN
}

// (AI GENERATED DESCRIPTION): Retrieves the configured advertisement data prefix (enc.Name) from the Config instance.
func (c *Config) AdvertisementDataPrefix() enc.Name {
	return c.advDataPfxN
}

// PrefixStatePrefix returns the prefix state sync prefix.
func (c *Config) PrefixStatePrefix() enc.Name {
	return c.pfxSyncGroupPfxN
}

func (c *Config) PrefixStateReplicationEnabled() bool {
	return c.PrefixStateReplicate
}

// (AI GENERATED DESCRIPTION): Returns the management prefix stored in the Config object.
func (c *Config) MgmtPrefix() enc.Name {
	return c.mgmtPrefix
}

// (AI GENERATED DESCRIPTION): Returns the advertisement synchronization interval from the configuration, converting the stored millisecond value into a `time.Duration`.
func (c *Config) AdvertisementSyncInterval() time.Duration {
	return time.Duration(c.AdvertisementSyncInterval_ms) * time.Millisecond
}

// (AI GENERATED DESCRIPTION): Returns the prefix synchronization interval from the configuration, converting the stored millisecond value into a `time.Duration`.
func (c *Config) PrefixSyncInterval() time.Duration {
	return time.Duration(c.PrefixSyncInterval_ms) * time.Millisecond
}

// (AI GENERATED DESCRIPTION): Returns the router dead interval configured in milliseconds, converting the `RouterDeadInterval_ms` field to a `time.Duration`.
func (c *Config) RouterDeadInterval() time.Duration {
	return time.Duration(c.RouterDeadInterval_ms) * time.Millisecond
}

// (AI GENERATED DESCRIPTION): Returns the slice of trust‑anchor names stored in the Config.
func (c *Config) TrustAnchorNames() []enc.Name {
	return c.trustAnchorsN
}

func (c *Config) PrefixInsertionTrustAnchorNames() []enc.Name {
	return c.prefixInsertionTrustAnchorsN
}

// (AI GENERATED DESCRIPTION): Returns the raw byte slice representing the configuration schema.
func (c *Config) SchemaBytes() []byte {
	return c.trustSchema
}

func (c *Config) PrefixInsertionSchemaBytes() []byte {
	return c.prefixInsertionTrustSchema
}

func (c *Config) readConfigBytes(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}
	if !filepath.IsAbs(path) && c.ConfigDir != "" {
		path = filepath.Join(c.ConfigDir, path)
	}
	return os.ReadFile(path)
}
