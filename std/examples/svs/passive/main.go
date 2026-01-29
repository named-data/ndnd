package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/sync"
)

// (AI GENERATED DESCRIPTION): Runs an SVS instance in passive mode that announces a group prefix, receives updates from other SVS nodes, buffers them in a Badger store, and logs each received update until the program is terminated.
func main() {
	// ===========================================================
	// IMPORTANT: Passive mode is not recommended for general use.
	// Only use this mode if you are familiar with SVS internals.
	// ===========================================================

	// This is an example of using SVS passive mode.
	// In passive mode, the SVS instance does not send any updates.
	// It only listens for updates from other SVS instances,
	// and buffers the updates received on the other instances to
	// help Sync state propagation.

	// Create a new engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err := app.Start()
	if err != nil {
		log.Fatal(nil, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// Create object client
	store, err := storage.NewBadgerStore("db-passive-svs")
	if err != nil {
		log.Error(nil, "Unable to create object store", "err", err)
		return
	}

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
		Client:            client,
		GroupPrefix:       group,
		SuppressionPeriod: 1 * time.Second,
		PeriodicTimeout:   5 * time.Minute,
		OnUpdate: func(ssu sync.SvSyncUpdate) {
			log.Info(nil, "Received update", "update", ssu)
		},
		Passive: true,
	})

	// Announce group prefix route
	client.AnnouncePrefix(ndn.Announcement{Name: group})
	defer client.WithdrawPrefix(group, nil)

	err = svsync.Start()
	if err != nil {
		log.Error(nil, "Unable to create SvSync", "err", err)
		return
	}
	defer svsync.Stop()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	<-sigchan
}
