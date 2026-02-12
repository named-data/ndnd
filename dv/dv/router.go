package dv

import (
	"os"
	"sync"
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	"github.com/named-data/ndnd/dv/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/trust_schema"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
	"github.com/named-data/ndnd/pid"
)

const PrefixSnapThreshold = 50

type Router struct {
	// go-ndn app that this router is attached to
	engine ndn.Engine
	// config for this router
	config *config.Config
	// trust configuration
	trust *sec.TrustConfig
	// object client
	client ndn.Client
	// whether to do prefix insertion
	enablePrefixInsertion bool
	// prefix insertion client
	prefixInsertionClient ndn.Client
	// nfd management thread
	nfdc *nfdc.NfdMgmtThread
	// single mutex for all operations
	mutex sync.Mutex

	// channel to stop the DV
	stop chan bool
	// heartbeat for outgoing Advertisements
	heartbeat *time.Ticker
	// deadcheck for neighbors
	deadcheck *time.Ticker

	// advertisement module
	advert advertModule

	// prefix table daemon
	pfx *pid.PrefixDaemon

	// neighbor table
	neighbors *table.NeighborTable
	// routing information base
	rib *table.Rib
	// forwarding table
	fib *table.Fib

	// map to track seen prefix insertion versions (prefix string -> version)
	seenPrefixVersions map[string]uint64
}

// Create a new DV router.
func NewRouter(config *config.Config, engine ndn.Engine) (*Router, error) {
	// Validate configuration
	err := config.Parse()
	if err != nil {
		return nil, err
	}

	// Create packet store
	store := storage.NewMemoryStore()

	// Create security configuration
	var trust *sec.TrustConfig = nil
	if config.KeyChainUri == "insecure" {
		log.Warn(nil, "Security is disabled - insecure mode")
	} else {
		kc, err := keychain.NewKeyChain(config.KeyChainUri, store)
		if err != nil {
			return nil, err
		}
		schema, err := trust_schema.NewLvsSchema(config.SchemaBytes())
		if err != nil {
			return nil, err
		}
		anchors := config.TrustAnchorNames()
		trust, err = sec.NewTrustConfig(kc, schema, anchors)
		if err != nil {
			return nil, err
		}

		// Attach data name as forwarding hint to cert Interests
		trust.UseDataNameFwHint = true
	}

	enablePrefixInsertion := config.PrefixInsertionSchemaPath != "deny"
	var prefixInsertionClient ndn.Client
	if enablePrefixInsertion {
		prefixInsertionStore := storage.NewMemoryStore()
		var prefixInsertionTrust *sec.TrustConfig = nil
		if config.PrefixInsertionSchemaPath == "insecure" || config.PrefixInsertionKeychainUri == "insecure" {
			log.Warn(nil, "Prefix insertion module is in allow-all mode")
		} else {
			kc, err := keychain.NewKeyChain(config.PrefixInsertionKeychainUri, prefixInsertionStore)
			if err != nil {
				return nil, err
			}
			schemaData, err := os.ReadFile(config.PrefixInsertionSchemaPath)
			if err != nil {
				return nil, err
			}
			schema, err := trust_schema.NewLvsSchema(schemaData)
			if err != nil {
				return nil, err
			}
			anchors := config.PrefixInsertionTrustAnchorNames()
			prefixInsertionTrust, err = sec.NewTrustConfig(kc, schema, anchors)
			if err != nil {
				return nil, err
			}
		}
		prefixInsertionClient = object.NewClient(engine, prefixInsertionStore, prefixInsertionTrust)
	} else {
		log.Warn(nil, "Prefix insertion is disabled")
	}

	// Create the DV router
	dv := &Router{
		engine:                engine,
		config:                config,
		trust:                 trust,
		client:                object.NewClient(engine, store, trust),
		enablePrefixInsertion: enablePrefixInsertion,
		prefixInsertionClient: prefixInsertionClient,
		nfdc:                  nfdc.NewNfdMgmtThread(engine),
		mutex:                 sync.Mutex{},
		seenPrefixVersions:    make(map[string]uint64),
	}

	// Initialize advertisement module
	dv.advert = advertModule{
		dv:       dv,
		bootTime: uint64(time.Now().Unix()),
		seq:      0,
		objDir:   storage.NewMemoryFifoDir(32), // keep last few advertisements
	}

	// Create prefix table
	dv.createPrefixTable()

	// Create DV tables
	dv.neighbors = table.NewNeighborTable(config, dv.nfdc)
	dv.rib = table.NewRib(config)
	dv.fib = table.NewFib(config, dv.nfdc)

	return dv, nil
}

// Log identifier for the DV router.
func (dv *Router) String() string {
	return "dv-router"
}

// Start the DV router. Blocks until Stop() is called.
func (dv *Router) Start() (err error) {
	log.Info(dv, "Starting DV router", "version", utils.NDNdVersion)
	defer log.Info(dv, "Stopped DV router")

	// Initialize channels
	dv.stop = make(chan bool, 1)

	// Register neighbor faces
	dv.createFaces()
	defer dv.destroyFaces()

	// Start timers
	dv.heartbeat = time.NewTicker(dv.config.AdvertisementSyncInterval())
	dv.deadcheck = time.NewTicker(dv.config.RouterDeadInterval())
	defer dv.heartbeat.Stop()
	defer dv.deadcheck.Stop()

	// Start object client
	dv.client.Start()
	defer dv.client.Stop()

	// Start management thread
	go dv.nfdc.Start()
	defer dv.nfdc.Stop()

	// Configure face
	if err = dv.configureFace(); err != nil {
		return err
	}

	// Register interest handlers
	if err = dv.register(); err != nil {
		return err
	}

	// Start prefix information daemon
	dv.pfx.Start()
	defer dv.pfx.Stop()

	// Add self to the RIB and make initial advertisement
	dv.rib.Set(dv.config.RouterName(), dv.config.RouterName(), 0)
	dv.advert.generate()

	// Initialize prefix table
	dv.pfx.Reset()

	for {
		select {
		case <-dv.heartbeat.C:
			dv.advert.sendSyncInterest()
		case <-dv.deadcheck.C:
			dv.checkDeadNeighbors()
		case <-dv.stop:
			return nil
		}
	}
}

// Stop the DV router.
func (dv *Router) Stop() {
	dv.stop <- true
}

// Configure the face to forwarder.
func (dv *Router) configureFace() (err error) {
	// Enable local fields on face. This includes incoming face indication.
	dv.nfdc.Exec(nfdc.NfdMgmtCmd{
		Module: "faces",
		Cmd:    "update",
		Args: &mgmt.ControlArgs{
			Mask:  optional.Some(mgmt.FaceFlagLocalFieldsEnabled),
			Flags: optional.Some(mgmt.FaceFlagLocalFieldsEnabled),
		},
		Retries: -1,
	})

	return nil
}

// Register interest handlers for DV prefixes.
func (dv *Router) register() (err error) {
	// Advertisement Sync (active)
	err = dv.engine.AttachHandler(dv.config.AdvertisementSyncActivePrefix(),
		func(args ndn.InterestHandlerArgs) {
			go dv.advert.OnSyncInterest(args, true)
		})
	if err != nil {
		return err
	}

	// Advertisement Sync (passive)
	err = dv.engine.AttachHandler(dv.config.AdvertisementSyncPassivePrefix(),
		func(args ndn.InterestHandlerArgs) {
			go dv.advert.OnSyncInterest(args, false)
		})
	if err != nil {
		return err
	}

	// Router management
	err = dv.engine.AttachHandler(dv.config.MgmtPrefix(),
		func(args ndn.InterestHandlerArgs) {
			go dv.mgmtOnInterest(args)
		})
	if err != nil {
		return err
	}

	insertPrefix := enc.NewGenericComponent("routing").
		Append(enc.NewGenericComponent("insert"))

	if dv.enablePrefixInsertion {
		err = dv.engine.AttachHandler(insertPrefix,
			func(args ndn.InterestHandlerArgs) {
				go dv.onInsertion(args)
			})
		if err != nil {
			return err
		}
	}

	// Register routes to forwarder
	pfxs := []enc.Name{
		dv.config.AdvertisementSyncPrefix(),
		dv.config.AdvertisementDataPrefix(),
		// TODO - expose sync prefix / data prefix
		// dv.pfxSvs.SyncPrefix(),
		// dv.pfxSvs.DataPrefix(),
		dv.config.MgmtPrefix(),
	}
	if dv.enablePrefixInsertion {
		pfxs = append(pfxs, insertPrefix)
	}

	for _, prefix := range pfxs {
		dv.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "register",
			Args: &mgmt.ControlArgs{
				Name:   prefix,
				Cost:   optional.Some(uint64(0)),
				Origin: optional.Some(config.NlsrOrigin),
			},
			Retries: -1,
		})
	}

	// Set strategy to multicast for sync prefixes
	pfxs = []enc.Name{
		dv.config.AdvertisementSyncPrefix(),
		// TODO - expose sync prefix / data prefix for svs
		// dv.pfxSvs.SyncPrefix(),
	}
	for _, prefix := range pfxs {
		dv.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "strategy-choice",
			Cmd:    "set",
			Args: &mgmt.ControlArgs{
				Name: prefix,
				Strategy: &mgmt.Strategy{
					Name: config.MulticastStrategy,
				},
			},
			Retries: -1,
		})
	}

	return nil
}

// createFaces creates faces to all neighbors.
func (dv *Router) createFaces() {
	for i, neighbor := range dv.config.Neighbors {
		var mtu optional.Optional[uint64]
		if neighbor.Mtu > 0 {
			mtu = optional.Some(neighbor.Mtu)
		}

		faceId, created, err := dv.nfdc.CreateFace(&mgmt.ControlArgs{
			Uri:             optional.Some(neighbor.Uri),
			FacePersistency: optional.Some(uint64(mgmt.PersistencyPermanent)),
			Mtu:             mtu,
		})
		if err != nil {
			log.Error(dv, "Failed to create face to neighbor", "uri", neighbor.Uri, "err", err)
			continue
		}
		log.Info(dv, "Created face to neighbor", "uri", neighbor.Uri, "faceId", faceId)

		dv.mutex.Lock()
		dv.config.Neighbors[i].FaceId = faceId
		dv.config.Neighbors[i].Created = created
		dv.mutex.Unlock()

		dv.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "register",
			Args: &mgmt.ControlArgs{
				Name:   dv.config.AdvertisementSyncActivePrefix(),
				Cost:   optional.Some(uint64(1)),
				Origin: optional.Some(config.NlsrOrigin),
				FaceId: optional.Some(faceId),
			},
			Retries: 3,
		})
	}
}

// destroyFaces synchronously destroys our faces to neighbors.
func (dv *Router) destroyFaces() {
	for _, neighbor := range dv.config.Neighbors {
		if neighbor.FaceId == 0 {
			continue
		}

		dv.engine.ExecMgmtCmd("rib", "unregister", &mgmt.ControlArgs{
			Name:   dv.config.AdvertisementSyncActivePrefix(),
			Origin: optional.Some(config.NlsrOrigin),
			FaceId: optional.Some(neighbor.FaceId),
		})

		// only destroy faces that we created
		if neighbor.Created {
			dv.engine.ExecMgmtCmd("faces", "destroy", &mgmt.ControlArgs{
				FaceId: optional.Some(neighbor.FaceId),
			})
		}
	}
}

// (AI GENERATED DESCRIPTION): Initializes the router’s prefix table by creating a subscription map, setting up an SVS synchronization agent (with snapshot support) for publishing updates, and constructing a local prefix table that forwards changes to the SVS.
func (dv *Router) createPrefixTable() {
	dv.pfx = pid.NewPrefixDaemon(dv.config, dv.client)
	// TODO - handle cleanup logic for de-allocation (unsubing)
	dv.pfx.OnChange(func() {
		dv.updateFib()
	})
}
