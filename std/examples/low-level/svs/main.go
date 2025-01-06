package main

import (
	"os"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/sync"
)

func main() {
	// Before running this example, make sure the strategy is correctly setup
	// to multicast for the /ndn/svs prefix. For example, using the following:
	//
	//   ndnd fw strategy set prefix=/ndn/svs strategy=/localhost/nfd/strategy/multicast
	//

	log.SetLevel(log.InfoLevel)
	logger := log.WithField("module", "main")

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <nodeId>", os.Args[0])
	}

	// Parse command line arguments
	nodeId, err := enc.NameFromStr(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid node ID: %s", os.Args[1])
	}

	// Create a new engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		logger.Fatalf("Unable to start engine: %+v", err)
		return
	}
	defer app.Stop()

	// Start SVS instance
	group, _ := enc.NameFromStr("/ndn/svs")
	svsync := sync.NewSvSync(app, group, func(ssu sync.SvSyncUpdate) {
		logger.Infof("Received update: %+v", ssu)
	})

	// Register group prefix route
	err = app.RegisterRoute(group)
	if err != nil {
		logger.Errorf("Unable to register route: %+v", err)
		return
	}
	defer app.UnregisterRoute(group)

	err = svsync.Start()
	if err != nil {
		logger.Errorf("Unable to create SvSync: %+v", err)
		return
	}

	// Publish new sequence number every second
	ticker := time.NewTicker(3 * time.Second)

	for range ticker.C {
		new := svsync.IncrSeqNo(nodeId)
		logger.Infof("Published new sequence number: %d", new)
	}
}
