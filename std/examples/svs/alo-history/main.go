package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	spec_repo "github.com/named-data/ndnd/repo/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/ndn/svs_ps"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	ndn_sync "github.com/named-data/ndnd/std/sync"
)

var group, _ = enc.NameFromStr("/ndn/svs")
var name enc.Name
var svsalo *ndn_sync.SvsALO
var store ndn.Store
var client ndn.Client
var repoName, _ = enc.NameFromStr("/ndnd/repo")

const SnapshotThreshold = 100

// (AI GENERATED DESCRIPTION): Runs an example chat application that joins an SVS ALO group with SnapshotNodeHistory, subscribes to all publications, announces its prefixes, and allows the user to send and receive chat messages over NDN.
func main() {
	// This example shows how to use the SVS ALO with the SnapshotNodeHistory.
	//
	// The SnapshotNodeHistory strategy will deliver all publications since the
	// node bootstrapped. This strategy is useful when the application cannot
	// take a snapshot of its state, and the publication history is important.
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
	var err error
	name, err = enc.NameFromStr(os.Args[1])
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

	// History snapshot works best with persistent storage
	ident := strings.ReplaceAll(name.String(), "/", "-")
	bstore, err := storage.NewBadgerStore(fmt.Sprintf("db-chat%s", ident))
	if err != nil {
		log.Error(nil, "Unable to create object store", "err", err)
		return
	}
	defer bstore.Close()
	store = bstore

	// Create object client
	client = object.NewClient(app, store, nil)
	if err = client.Start(); err != nil {
		log.Error(nil, "Unable to start object client", "err", err)
		return
	}
	defer client.Stop()

	// Create a new SVS ALO instance
	svsalo, err = ndn_sync.NewSvsALO(ndn_sync.SvsAloOpts{
		// Name is the name of the node
		Name: name,

		// Initial state is the state of the node
		InitialState: readState(),

		// Svs is the Sync group options
		Svs: ndn_sync.SvSyncOpts{
			Client:      client,
			GroupPrefix: group,
		},

		// This strategy internally takes regular snapshots of the entire history
		// of publications for this node. At the application layer, all publications
		// since the node bootstrapped will be delivered.
		Snapshot: &ndn_sync.SnapshotNodeHistory{
			Client:    client,
			Threshold: SnapshotThreshold,
		},
	})
	if err != nil {
		panic(err)
	}

	// OnError gets called when we get an error from the SVS ALO instance.
	svsalo.SetOnError(func(err error) {
		fmt.Fprintf(os.Stderr, "*** %v\n", err)
	})

	// Subscribe to all publications
	svsalo.SubscribePublisher(enc.Name{}, func(pub ndn_sync.SvsPub) {
		if !pub.IsSnapshot {
			// Normal publication, just print it
			fmt.Printf("%s: %s\n", pub.Publisher, pub.Bytes())
		} else {
			// Snapshot publication, unwrap and print all messages
			snapshot, err := svs_ps.ParseHistorySnap(enc.NewWireView(pub.Content), true)
			if err != nil {
				panic(err) // undefined behavior after this point
			}

			fmt.Fprintf(os.Stderr, "*** Snapshot from %s with %d entries\n",
				pub.Publisher, len(snapshot.Entries))

			// Print all messages in the snapshot
			for _, entry := range snapshot.Entries {
				fmt.Printf("%s: %s\n", pub.Publisher, entry.Content.Join())
			}
		}

		// Commit the state after processing the publication
		commitState(pub.State)
	})

	// Announce our name prefixes to the network
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

	// This step is OPTIONAL, if you want to persist the group data to the repo.
	//
	// In a real application, you would need the right security configuration
	// to allow the repo to accept this command.
	//
	// This command will fail with a log if repo is not running, or
	// does not respond to the command.
	client.ExpressCommand(
		repoName.Append(enc.NewKeywordComponent("cmd")),
		name.Append(enc.NewKeywordComponent("repo")),
		(&spec_repo.RepoCmd{
			SyncJoin: &spec_repo.SyncJoin{
				Protocol: &spec.NameContainer{Name: spec_repo.SyncProtocolSvsV3},
				Group:    &spec.NameContainer{Name: group},
				HistorySnapshot: &spec_repo.HistorySnapshotConfig{
					Threshold: SnapshotThreshold,
				},
			},
		}).Encode(),
		func(w enc.Wire, err error) {
			if err != nil {
				log.Warn(nil, "Repo sync join command failed", "err", err)
			} else {
				log.Info(nil, "Repo joined SVS group")
			}
		})

	// Joined the group - now we can start the chat
	fmt.Fprintln(os.Stderr, "*** Joined SVS ALO chat group")
	fmt.Fprintln(os.Stderr, "*** You are:", name)
	fmt.Fprintln(os.Stderr, "*** Type a message and press enter to send.")
	fmt.Fprintln(os.Stderr, "*** Press Ctrl+C to exit.")
	fmt.Fprintln(os.Stderr)

	// Publish an initial message to announce our presence
	publish([]byte("Entered the chat room"))

	counter := 1
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

		// Testing - use !! to send 100 messages after counter
		if string(line) == "!!" {
			for range 100 {
				publish(fmt.Appendf(nil, "Message %d", counter))
				counter++
			}
			continue
		}

		// Testing - use + to publish a blob fetch command
		if strings.HasPrefix(string(line), "+") {
			publishBlob(line)
			continue
		}

		publish(line)
	}
}

// publish sends a publication to the SVS ALO group
func publish(content []byte) {
	_, state, err := svsalo.Publish(enc.Wire{content})
	if err != nil {
		log.Error(nil, "Unable to publish message", "err", err)
	}

	// Commit the state after processing our own publication
	commitState(state)
}

// publishBlob creates a new blob and publishes a BlobFetch command for repo
func publishBlob(content []byte) {
	// To be reachable on the network, we produce the blob under
	// the data prefix of the SVS ALO group.
	// Repo requires that all blobs be under the group prefix, this
	// automatically satisfies that requirement.
	blobName := svsalo.DataPrefix().
		Append(enc.NewKeywordComponent("blob")).
		WithVersion(enc.VersionUnixMicro)

	verName, err := client.Produce(ndn.ProduceArgs{
		Name:    blobName,
		Content: enc.Wire{content},
	})
	if err != nil {
		log.Error(nil, "Unable to publish blob", "err", err)
		return
	}

	// Publish a BlobFetch command for repo to the group
	// This will trigger repo to fetch the published blob
	cmd := spec_repo.RepoCmd{
		BlobFetch: &spec_repo.BlobFetch{
			Name: &spec.NameContainer{Name: verName},
		},
	}
	publish(cmd.Encode().Join())
}

// (AI GENERATED DESCRIPTION): Commits the provided state to the NDN object store under the current Sync group, persisting the state atomically.
func commitState(state enc.Wire) {
	// Once a publication is processed, ideally the application should persist
	// it's own state and the state of the Sync group *atomically*.
	//
	// Applications can use their own data structures to store the state.
	// In this example, we use the NDN object store to persist the state.
	store.Put(group, state.Join())
}

// (AI GENERATED DESCRIPTION): Retrieves the persisted state from the object store and returns it as an `enc.Wire`, or `nil` if no state has been stored.
func readState() enc.Wire {
	// Read the state from the object store
	// See commitState for more information
	stateWire, err := store.Get(group, false)
	if err != nil {
		panic("unable to get state (store is broken)")
	}
	if stateWire == nil {
		return nil
	}
	return enc.Wire{stateWire}
}
