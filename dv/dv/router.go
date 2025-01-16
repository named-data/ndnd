package dv

import (
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
	ndn_sync "github.com/named-data/ndnd/std/sync"
	"github.com/named-data/ndnd/std/utils"
)

type Router struct {
	// go-ndn app that this router is attached to
	engine ndn.Engine
	// config for this router
	config *config.Config
	// object client
	client *object.Client
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

	// neighbor table
	neighbors *table.NeighborTable
	// routing information base
	rib *table.Rib
	// prefix table
	pfx *table.PrefixTable
	// forwarding table
	fib *table.Fib

	// advertisement module
	advert advertModule
	// prefix table svs instance
	pfxSvs *ndn_sync.SvSync
}

// Create a new DV router.
func NewRouter(config *config.Config, engine ndn.Engine) (*Router, error) {
	// Validate configuration
	err := config.Parse()
	if err != nil {
		return nil, err
	}

	// Create the DV router
	dv := &Router{
		engine: engine,
		config: config,
		client: object.NewClient(engine, object.NewMemoryStore()),
		nfdc:   nfdc.NewNfdMgmtThread(engine),
		mutex:  sync.Mutex{},
	}

	// Initialize advertisement module
	dv.advert = advertModule{
		dv:       dv,
		bootTime: uint64(time.Now().Unix()),
		seq:      0,
		objDir:   object.NewMemoryFifoDir(32), // keep last few advertisements
	}

	// Create sync groups
	dv.pfxSvs = ndn_sync.NewSvSync(ndn_sync.SvSyncOpts{
		Engine:      engine,
		GroupPrefix: config.PrefixTableSyncPrefix(),
		OnUpdate:    func(ssu ndn_sync.SvSyncUpdate) { go dv.onPfxSyncUpdate(ssu) },
		BootTime:    dv.advert.bootTime,
	})

	// Create tables
	dv.neighbors = table.NewNeighborTable(config, dv.nfdc)
	dv.rib = table.NewRib(config)
	dv.pfx = table.NewPrefixTable(config, dv.client, dv.pfxSvs)
	dv.fib = table.NewFib(config, dv.nfdc)

	return dv, nil
}

// Log identifier for the DV router.
func (dv *Router) String() string {
	return "dv-router"
}

// Start the DV router. Blocks until Stop() is called.
func (dv *Router) Start() (err error) {
	log.Info(dv, "Starting router")
	defer log.Info(dv, "Stopping router")

	// Initialize channels
	dv.stop = make(chan bool, 1)

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
	err = dv.configureFace()
	if err != nil {
		return err
	}

	// Register interest handlers
	err = dv.register()
	if err != nil {
		return err
	}

	// Start sync groups
	dv.pfxSvs.Start()
	defer dv.pfxSvs.Stop()

	// Add self to the RIB and make initial advertisement
	dv.rib.Set(dv.config.RouterName(), dv.config.RouterName(), 0)
	dv.advert.generate()

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
			Mask:  utils.IdPtr(mgmt.FaceFlagLocalFieldsEnabled),
			Flags: utils.IdPtr(mgmt.FaceFlagLocalFieldsEnabled),
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

	// Readvertise Data
	err = dv.engine.AttachHandler(dv.config.ReadvertisePrefix(),
		func(args ndn.InterestHandlerArgs) {
			go dv.readvertiseOnInterest(args)
		})
	if err != nil {
		return err
	}

	// Router status
	err = dv.engine.AttachHandler(dv.config.StatusPrefix(),
		func(args ndn.InterestHandlerArgs) {
			go dv.statusOnInterest(args)
		})
	if err != nil {
		return err
	}

	// Register routes to forwarder
	pfxs := []enc.Name{
		dv.config.AdvertisementSyncPrefix(),
		dv.config.AdvertisementDataPrefix(),
		dv.config.PrefixTableSyncPrefix(),
		dv.config.PrefixTableDataPrefix(),
		dv.config.LocalPrefix(),
	}
	for _, prefix := range pfxs {
		dv.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "register",
			Args: &mgmt.ControlArgs{
				Name:   prefix,
				Cost:   utils.IdPtr(uint64(0)),
				Origin: utils.IdPtr(config.NlsrOrigin),
			},
			Retries: -1,
		})
	}

	// Set strategy to multicast for sync prefixes
	pfxs = []enc.Name{
		dv.config.AdvertisementSyncPrefix(),
		dv.config.PrefixTableSyncPrefix(),
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
