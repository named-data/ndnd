package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	ndn_sync "github.com/named-data/ndnd/std/sync"
)

// (AI GENERATED DESCRIPTION): Runs an example SVS ALO chat client that joins a sync group, publishes and receives messages using the SnapshotNodeLatest strategy, and handles subscriptions and error recovery.
func main() {
	// This example shows how to use the SVS ALO with the SnapshotNodeLatest.
	//
	// The SnapshotNodeLatest strategy will only deliver the latest snapshot
	// and all publications after the snapshot. This strategy is useful when
	// the application can take a snapshot of its state and send it to other
	// nodes, so that the publication history can be pruned
	//
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
	group, _ := enc.NameFromStr("/ndn/svs")
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
	client := object.NewClient(app, storage.NewMemoryStore(), nil)
	if err = client.Start(); err != nil {
		log.Error(nil, "Unable to start object client", "err", err)
		return
	}
	defer client.Stop()

	// Total number and size of messages
	msgCount := 0
	msgSize := 0

	// Create a new SVS ALO instance
	svsalo, err := ndn_sync.NewSvsALO(ndn_sync.SvsAloOpts{
		// Name is the name of the node
		Name: name,

		// Svs is the Sync group options
		Svs: ndn_sync.SvSyncOpts{
			Client:      client,
			GroupPrefix: group,
		},

		// The snapshot strategy provides a way to prevent slowly aggregating
		// old publications to arrive at the application's current state.
		//
		// The SnapshotNodeLatest strategy will only deliver the latest snapshot
		// and all publications after the snapshot. As a result, the snapshot
		// in this case should contain the entire state of the node.
		Snapshot: &ndn_sync.SnapshotNodeLatest{
			Client: client,
			SnapMe: func(enc.Name) (enc.Wire, error) {
				// In this example, we will ignore the old messages
				// and only send a message with the total number of messages.
				//
				// A real application can bundle all state of the node in
				// the snapshot publication.
				message := fmt.Sprintf("Skipping %d messages with %d bytes", msgCount, msgSize)

				return enc.Wire{[]byte(message)}, nil
			},
			Threshold: 10,
		},
	})
	if err != nil {
		panic(err)
	}

	// Set of publishers that we are subscribed to.
	// The value is the number of errors received for the publisher.
	subs := make(map[uint64]int)

	// OnPublisher gets called when we get some update from a publisher.
	// This includes publishers we are not subscribed to.
	//
	// You can also alternatively subscribe to the empty name enc.Name{}
	// to receive all publications. This will, however, make it impossible
	// to subscribe to specific publishers if they are unreachable or
	// returning errros.
	svsalo.SetOnPublisher(func(publisher enc.Name) {
		// If we get a new update, subscribe to the publisher
		publisherHash := publisher.Hash()
		if _, ok := subs[publisherHash]; !ok {
			subs[publisherHash] = 0
			fmt.Fprintf(os.Stderr, "*** Subscribing to %s\n", publisher)

			// Both normal and snapshot publications will be received here.
			// Snapshots will have the IsSnapshot flag set to true.
			// The publications will be received in the order they were published.
			//
			// Since the snapshot strategy is set to SnapshotNodeLatest,
			// older publications before a snapshot will be ignored.
			//
			// Note that for other snapshot strategies, the snapshot may be delivered
			// under a separate name prefix (e.g. if it affects multiple publishers).
			svsalo.SubscribePublisher(publisher, func(pub ndn_sync.SvsPub) {
				tag := ""
				if pub.IsSnapshot {
					tag = "[snapshot] "
				}

				fmt.Printf("%s%s: %s\n", tag, pub.Publisher, pub.Bytes())

				// Reset the error counter (see OnError below)
				subs[publisherHash] = 0
			})
		}
	})

	// OnError gets called when we get an error from the SVS ALO instance.
	// If we get more than three errors from a publisher, we will stop
	// subscribing to that publisher.
	svsalo.SetOnError(func(err error) {
		errSync := &ndn_sync.ErrSync{}
		if errors.As(err, &errSync) {
			hash := errSync.Publisher.Hash()
			if _, ok := subs[hash]; !ok {
				return // not subscribed
			}

			subs[hash]++
			if subs[hash] >= 3 {
				fmt.Fprintf(os.Stderr, "*** Unsubscribing from %s (too many errors)\n", errSync.Publisher)
				svsalo.UnsubscribePublisher(errSync.Publisher)
				delete(subs, hash)
				return
			}
		}

		fmt.Fprintf(os.Stderr, "*** %v\n", err)
	})

	// Announce routes to the local forwarder
	for _, route := range []enc.Name{
		svsalo.SyncPrefix(),
		svsalo.DataPrefix(),
	} {
		client.AnnouncePrefix(ndn.Announcement{Name: route})
		defer client.WithdrawPrefix(route, nil)
	}

	if err = svsalo.Start(); err != nil {
		log.Error(nil, "Unable to start SVS ALO", "err", err)
		return
	}
	defer svsalo.Stop()

	fmt.Fprintln(os.Stderr, "*** Joined SVS ALO chat group")
	fmt.Fprintln(os.Stderr, "*** You are:", name)
	fmt.Fprintln(os.Stderr, "*** Type a message and press enter to send.")
	fmt.Fprintln(os.Stderr, "*** Press Ctrl+C to exit.")
	fmt.Fprintln(os.Stderr)

	// Publish an initial empty message to announce our presence
	_, _, err = svsalo.Publish(enc.Wire{})
	if err != nil {
		log.Error(nil, "Unable to publish message", "err", err)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		// Read chat message from stdin
		line, err := reader.ReadBytes('\n')
		if err != nil {
			log.Error(nil, "Unable to read line", "err", err)
			return
		}

		// Trim newline character
		line = line[:len(line)-1]
		if len(line) == 0 {
			continue
		}

		// Publish chat message
		msgCount++
		msgSize += len(line)
		_, _, err = svsalo.Publish(enc.Wire{line})
		if err != nil {
			log.Error(nil, "Unable to publish message", "err", err)
		}
	}
}
