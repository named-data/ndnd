package cmd

import (
	"fmt"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/dv"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/ndn"
)

type DvExecutor struct {
	engine ndn.Engine
	router *dv.Router
}

// (AI GENERATED DESCRIPTION): Initializes a new `DvExecutor` by validating the supplied configuration, starting a basic NDN engine, and creating the DV router.
func NewDvExecutor(config *config.Config) (*DvExecutor, error) {
	dve := new(DvExecutor)

	// Validate configuration sanity
	err := config.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to validate dv config: %w", err)
	}

	// Start NDN engine
	dve.engine = engine.NewBasicEngine(engine.NewDefaultFace())

	// Create the DV router
	dve.router, err = dv.NewRouter(config, dve.engine)
	if err != nil {
		return nil, fmt.Errorf("failed to create dv router: %w", err)
	}

	return dve, nil
}

// (AI GENERATED DESCRIPTION): Starts the DV engine and then the router, blocking indefinitely until the router stops, and panics if either component fails to start, ensuring the engine is stopped when the function exits.
func (dve *DvExecutor) Start() {
	err := dve.engine.Start()
	if err != nil {
		panic(fmt.Errorf("failed to start dv engine: %w", err))
	}
	defer dve.engine.Stop()

	err = dve.router.Start() // blocks forever
	if err != nil {
		panic(fmt.Errorf("failed to start dv router: %w", err))
	}
}

// (AI GENERATED DESCRIPTION): Stops the DvExecutor by shutting down its underlying router.
func (dve *DvExecutor) Stop() {
	dve.router.Stop()
}

// (AI GENERATED DESCRIPTION): Returns the `dv.Router` instance associated with this `DvExecutor`.
func (dve *DvExecutor) Router() *dv.Router {
	return dve.router
}
