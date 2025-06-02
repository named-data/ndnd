package config

import (
	_ "embed"
	"fmt"
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
	// Time after which a neighbor is considered dead.
	RouterDeadInterval_ms uint64 `json:"router_dead_interval"`
	// URI specifying KeyChain location.
	KeyChainUri string `json:"keychain"`
	// List of trust anchor full names.
	TrustAnchors []string `json:"trust_anchors"`
	// Path to trust schema for prefix insertion.
	PrefixInsertionSchemaPath string `json:"prefix_insertion_schema"`
	// URI specifying KeyChain location for prefix insertion verifier.
	PrefixInsertionKeychainUri string `json:"prefix_insertion_keychain"`
	// List of trust anchor full names for prefix insertion.
	PrefixInsertionTrustAnchors []string `json:"prefix_insertion_trust_anchors"`
	// List of permanent neighbors.
	Neighbors []Neighbor `json:"neighbors"`

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
	// Prefix Table Sync Prefix
	pfxSyncGroupPfxN enc.Name
	// NLSR readvertise prefix
	mgmtPrefix enc.Name
	// Trust anchor names
	trustAnchorsN []enc.Name
	// Prefix Insertion trust anchor names
	prefixInsertionTrustAnchorsN []enc.Name
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

func DefaultConfig() *Config {
	return &Config{
		Network:                      "", // invalid
		Router:                       "", // invalid
		AdvertisementSyncInterval_ms: 5000,
		RouterDeadInterval_ms:        30000,
		KeyChainUri:                  "undefined",
		PrefixInsertionSchemaPath:    "deny",
		PrefixInsertionKeychainUri:   "undefined",
	}
}

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

	// Prefix table sync prefix
	c.pfxSyncGroupPfxN = c.networkNameN.
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("PFS"))

	// Local prefixes to NFD
	c.mgmtPrefix = enc.LOCALHOST.
		Append(enc.NewGenericComponent("nlsr"))

	return nil
}

func (c *Config) NetworkName() enc.Name {
	return c.networkNameN
}

func (c *Config) RouterName() enc.Name {
	return c.routerNameN
}

func (c *Config) AdvertisementSyncPrefix() enc.Name {
	return c.advSyncPfxN
}

func (c *Config) AdvertisementSyncActivePrefix() enc.Name {
	return c.advSyncActivePfxN
}

func (c *Config) AdvertisementSyncPassivePrefix() enc.Name {
	return c.advSyncPassivePfxN
}

func (c *Config) AdvertisementDataPrefix() enc.Name {
	return c.advDataPfxN
}

func (c *Config) PrefixTableGroupPrefix() enc.Name {
	return c.pfxSyncGroupPfxN
}

func (c *Config) MgmtPrefix() enc.Name {
	return c.mgmtPrefix
}

func (c *Config) AdvertisementSyncInterval() time.Duration {
	return time.Duration(c.AdvertisementSyncInterval_ms) * time.Millisecond
}

func (c *Config) RouterDeadInterval() time.Duration {
	return time.Duration(c.RouterDeadInterval_ms) * time.Millisecond
}

func (c *Config) TrustAnchorNames() []enc.Name {
	return c.trustAnchorsN
}

func (c *Config) PrefixInsertionTrustAnchorNames() []enc.Name {
	return c.prefixInsertionTrustAnchorsN
}

func (c *Config) SchemaBytes() []byte {
	return SchemaBytes
}
