package config

import (
	_ "embed"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

const CostInfinity = uint64(16)
const NlsrOrigin = uint64(mgmt.RouteOriginNLSR)

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
	// Path to trust schema for prefix injection.
	PrefixInjectionSchemaPath string `json:"prefix_injection_schema"`
	// URI specifying KeyChain location for prefix injection verifier.
	PrefixInjectionKeychainUri string `json:"prefix_injection_keychain"`
	// List of trust anchor full names for prefix injection.
	PrefixInjectionTrustAnchors []string `json:"prefix_injection_trust_anchors"`
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
	// Universal router data prefix
	routerDataPfxN enc.Name
	// Prefix Table Sync Prefix
	pfxSyncPfxN enc.Name
	// Prefix Table Data Prefix
	pfxDataPfxN enc.Name
	// NLSR readvertise prefix
	mgmtPrefix enc.Name
	// Trust anchor names
	trustAnchorsN []enc.Name
	// Prefix Injection trust anchor names
	prefixInjectionTrustAnchorsN []enc.Name
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
		PrefixInjectionSchemaPath:    "insecure",
		PrefixInjectionKeychainUri:   "insecure",
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

	c.prefixInjectionTrustAnchorsN = make([]enc.Name, 0, len(c.PrefixInjectionTrustAnchors))
	for _, anchor := range c.PrefixInjectionTrustAnchors {
		name, err := enc.NameFromStr(anchor)
		if err != nil {
			return err
		}
		c.prefixInjectionTrustAnchorsN = append(c.prefixInjectionTrustAnchorsN, name)
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
	c.pfxSyncPfxN = c.networkNameN.
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("PFS"))

	// Router data prefix including prefix data and certificates
	c.routerDataPfxN = c.routerNameN.
		Append(enc.NewKeywordComponent("DV"))
	c.pfxDataPfxN = c.routerNameN.
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("PFX"))

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

func (c *Config) RouterDataPrefix() enc.Name {
	return c.routerDataPfxN
}

func (c *Config) PrefixTableSyncPrefix() enc.Name {
	return c.pfxSyncPfxN
}

func (c *Config) PrefixTableDataPrefix() enc.Name {
	return c.pfxDataPfxN
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

func (c *Config) PrefixInjectionTrustAnchorNames() []enc.Name {
	return c.prefixInjectionTrustAnchorsN
}

func (c *Config) SchemaBytes() []byte {
	return SchemaBytes
}
