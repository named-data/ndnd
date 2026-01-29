package main

import (
	"fmt"
	"os"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/sync"
)

// (AI GENERATED DESCRIPTION): Launches an SVSync client that announces the `/ndn/svs` prefix and publishes a new sequence number for the supplied node name every three seconds.
func main() {
	// Before running this example, make sure the strategy is correctly setup
	// to multicast for the sync prefix. For example, using the following:
	//
	//   ndnd fw strategy-set prefix=/ndn/svs/32=svs strategy=/localhost/nfd/strategy/multicast
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

	// Create object client
	store := storage.NewMemoryStore()
	client := object.NewClient(app, store, nil)
	err = client.Start()
	if err != nil {
		log.Error(nil, "Unable to start object client", "err", err)
		return
	}
	defer client.Stop()

	// Start SVS instance
	group, _ := enc.NameFromStr("/ndn/svs")
	svsync := sync.NewSvSync(sync.SvSyncOpts{
		Client:      client,
		GroupPrefix: group,
		OnUpdate: func(ssu sync.SvSyncUpdate) {
			log.Info(nil, "Received update", "update", ssu)
		},
	})

	// Announce group prefix route
	client.AnnouncePrefix(ndn.Announcement{Name: group})
	defer client.WithdrawPrefix(group, nil)

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
