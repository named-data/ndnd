package repo

import (
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/trust_schema"
)

type Repo struct {
	config *Config

	engine ndn.Engine
	store  ndn.Store
	client ndn.Client

	keychain ndn.KeyChain
	trust    *sec.TrustConfig

	groupsSvs map[string]*RepoSvs
	mutex     sync.Mutex
}

// (AI GENERATED DESCRIPTION): Creates a new Repo instance, initializing it with the supplied configuration and an empty map for its groupsSvs.
func NewRepo(config *Config) *Repo {
	return &Repo{
		config:    config,
		groupsSvs: make(map[string]*RepoSvs),
	}
}

// (AI GENERATED DESCRIPTION): Returns the string `"repo"` as the string representation of a `Repo` instance.
func (r *Repo) String() string {
	return "repo"
}

// (AI GENERATED DESCRIPTION): Initializes and starts the NDN data repository by setting up storage, network engine, keychain, trust configuration, and object client, then attaching the management command handler and announcing its prefix.
func (r *Repo) Start() (err error) {
	log.Info(r, "Starting NDN Data Repository", "dir", r.config.StorageDir)

	// Make object store database
	r.store, err = storage.NewBadgerStore(r.config.StorageDir + "/badger")
	if err != nil {
		return err
	}

	// Create NDN engine
	r.engine = engine.NewBasicEngine(engine.NewDefaultFace())
	r.setupEngineHook()
	if err = r.engine.Start(); err != nil {
		return err
	}

	kc, err := keychain.NewKeyChain(r.config.KeyChainUri, r.store)
	if err != nil {
		return err
	}
	r.keychain = kc

	// TODO: enforce trust schema defined by repo provider
	schema := trust_schema.NewNullSchema()

	// TODO: handle app-specific case
	anchors := r.config.TrustAnchorNames()

	// Create trust config
	trust, err := sec.NewTrustConfig(kc, schema, anchors)
	if err != nil {
		return err
	}
	r.trust = trust

	// Attach data name as forwarding hint to cert Interests
	// TODO: what to do if this is app dependent? Separate client for each app?
	trust.UseDataNameFwHint = true

	// Start NDN Object API client
	r.client = object.NewClient(r.engine, r.store, trust)
	if err := r.client.Start(); err != nil {
		return err
	}

	// Attach managmemt interest handler
	if err := r.client.AttachCommandHandler(r.config.NameN, r.onMgmtCmd); err != nil {
		return err
	}
	r.client.AnnouncePrefix(ndn.Announcement{
		Name:   r.config.NameN,
		Expose: true,
	})

	return nil
}

// (AI GENERATED DESCRIPTION): Stops the NDN data repository by halting all service groups, deregistering its prefix, detaching the command handler, and stopping the underlying client and engine.
func (r *Repo) Stop() error {
	log.Info(r, "Stopping NDN Data Repository")

	for _, svs := range r.groupsSvs {
		svs.Stop()
	}
	clear(r.groupsSvs)

	r.client.WithdrawPrefix(r.config.NameN, nil)
	if err := r.client.DetachCommandHandler(r.config.NameN); err != nil {
		log.Warn(r, "Failed to detach command handler", "err", err)
	}

	if r.client != nil {
		r.client.Stop()
	}
	if r.engine != nil {
		r.engine.Stop()
	}

	return nil
}

// setupEngineHook sets up the hook to persist all data.
func (r *Repo) setupEngineHook() {
	r.engine.(*basic.Engine).OnDataHook = func(data ndn.Data, raw enc.Wire, sigCov enc.Wire) error {
		// This is very hacky, improve if possible.
		// Assume that if there is a version it is the second-last component.
		// We might not want to store non-versioned data anyway (?)
		if ver := data.Name().At(-2); ver.IsVersion() {
			log.Trace(r, "Storing data", "name", data.Name())
			return r.store.Put(data.Name(), raw.Join())
		} else {
			log.Trace(r, "Ignoring non-versioned data", "name", data.Name())
		}
		return nil
	}
}
