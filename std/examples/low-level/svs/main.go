package main

import (
	"fmt"
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

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <name>", os.Args[0])
		os.Exit(1)
	}

	// Parse command line arguments
	name, err := enc.NameFromStr(os.Args[1])
	if err != nil {
		log.Fatal(nil, "Invalid node ID", "name", os.Args[1])
		return
	}

	// Create a new engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		log.Fatal(nil, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// Start SVS instance
	group, _ := enc.NameFromStr("/ndn/svs")
	svsync := sync.NewSvSync(sync.SvSyncOpts{
		Engine:      app,
		GroupPrefix: group,
		OnUpdate: func(ssu sync.SvSyncUpdate) {
			log.Info(nil, "Received update", "update", ssu)
		},
	})

	// Register group prefix route
	err = app.RegisterRoute(group)
	if err != nil {
		log.Error(nil, "Unable to register route", "err", err)
		return
	}
	defer app.UnregisterRoute(group)

	err = svsync.Start()
	if err != nil {
		log.Error(nil, "Unable to create SvSync", "err", err)
		return
	}

	// Publish new sequence number every second
	ticker := time.NewTicker(3 * time.Second)

	for range ticker.C {
		seq := svsync.IncrSeqNo(name)
		log.Info(nil, "Published new sequence number", "seq", seq)
	}
}
