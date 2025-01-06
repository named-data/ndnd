package executor

import (
	"errors"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/dv"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/ndn"
)

type DvConfig struct {
	Config *config.Config `json:"dv"`
}

func DefaultConfig() DvConfig {
	return DvConfig{
		Config: config.DefaultConfig(),
	}
}

func (dc DvConfig) Parse() error {
	return dc.Config.Parse()
}

type DvExecutor struct {
	engine ndn.Engine
	router *dv.Router
}

func NewDvExecutor(dc DvConfig) (*DvExecutor, error) {
	dve := new(DvExecutor)

	// Validate configuration sanity
	err := dc.Parse()
	if err != nil {
		return nil, errors.New("failed to validate dv config: " + err.Error())
	}

	// Start NDN engine
	dve.engine = engine.NewBasicEngine(engine.NewDefaultFace())

	// Create the DV router
	dve.router, err = dv.NewRouter(dc.Config, dve.engine)
	if err != nil {
		return nil, errors.New("failed to create dv router: " + err.Error())
	}

	return dve, nil
}

func (dve *DvExecutor) Start() error {
	err := dve.engine.Start()
	if err != nil {
		return errors.New("failed to start dv app: " + err.Error())
	}
	defer dve.engine.Stop()

	err = dve.router.Start() // blocks forever
	if err != nil {
		return errors.New("failed to start dv router: " + err.Error())
	}

	return nil
}

func (dve *DvExecutor) Stop() {
	dve.router.Stop()
}

func (dve *DvExecutor) Router() *dv.Router {
	return dve.router
}
