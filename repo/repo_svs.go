package repo

import (
	"fmt"
	"time"

	"github.com/named-data/ndnd/repo/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/ndn/svs_ps"
	ndn_sync "github.com/named-data/ndnd/std/sync"
	"github.com/named-data/ndnd/std/types/optional"
)

type RepoSvs struct {
	config *Config
	client ndn.Client
	cmd    *tlv.SyncJoin
	svsalo *ndn_sync.SvsALO
}

// (AI GENERATED DESCRIPTION): Creates a new `RepoSvs` instance initialized with the given configuration, NDN client, and SyncJoin command.
func NewRepoSvs(config *Config, client ndn.Client, cmd *tlv.SyncJoin) *RepoSvs {
	return &RepoSvs{
		config: config,
		client: client,
		cmd:    cmd,
		svsalo: nil,
	}
}

// (AI GENERATED DESCRIPTION): Generates a human‑readable string identifying the repo‑svs instance, displaying its associated group name.
func (r *RepoSvs) String() string {
	return fmt.Sprintf("repo-svs (%s)", r.cmd.Group.Name)
}

func (r *RepoSvs) Client() ndn.Client {
	return r.client
}

// (AI GENERATED DESCRIPTION): Initializes and starts the repository SVS ALO, configuring snapshots, multicast, prefix announcements, and publisher subscriptions.
func (r *RepoSvs) Start() (err error) {
	log.Info(r, "Starting SVS")

	// Parse snapshot configuration
	var snapshot ndn_sync.Snapshot = nil

	// History snapshot
	if r.cmd.HistorySnapshot != nil {
		if t := r.cmd.HistorySnapshot.Threshold; t < 10 {
			return fmt.Errorf("invalid history snapshot threshold: %d", t)
		}

		snapshot = &ndn_sync.SnapshotNodeHistory{
			Client:         r.client,
			Threshold:      r.cmd.HistorySnapshot.Threshold,
			IsRepo:         true,
			IgnoreValidity: optional.Some(r.config.IgnoreValidity),
		}
	}

	// As of writing this, this is no way to get multicast without specifying
	// a prefix (fw strategy is implemented only for prefixes)
	var multicastPrefix enc.Name = nil
	if r.cmd.MulticastPrefix != nil {
		multicastPrefix = r.cmd.MulticastPrefix.Name
	}

	// Start SVS ALO
	r.svsalo, err = ndn_sync.NewSvsALO(ndn_sync.SvsAloOpts{
		Name:         enc.Name{enc.NewKeywordComponent("repo")}, // unused
		InitialState: r.readState(),
		Svs: ndn_sync.SvSyncOpts{
			Client:            r.client,
			GroupPrefix:       r.cmd.Group.Name,
			SuppressionPeriod: 500 * time.Millisecond,
			PeriodicTimeout:   365 * 24 * time.Hour, // basically never
			Passive:           true,
			IgnoreValidity:    optional.Some(r.config.IgnoreValidity),
		},
		Snapshot:        snapshot,
		MulticastPrefix: multicastPrefix,
	})
	if err != nil {
		return err
	}

	// Set error handler
	r.svsalo.SetOnError(func(err error) {
		log.Error(r, "SVS ALO error", "err", err)
	})

	// Subscribe to all publishers
	r.svsalo.SubscribePublisher(enc.Name{}, func(pub ndn_sync.SvsPub) {
		if pub.IsSnapshot {
			// Each type of snapshot has separate handling.
			if r.cmd.HistorySnapshot != nil {
				snapshot, err := svs_ps.ParseHistorySnap(enc.NewWireView(pub.Content), true)
				if err != nil {
					panic(err) // impossible, encoded by us
				}

				for _, entry := range snapshot.Entries {
					r.processIncomingPub(entry.Content)
				}
			}
		} else {
			// Process the publication.
			r.processIncomingPub(pub.Content)
		}

		r.commitState(pub.State)
	})

	// This covers both the sync prefix and all producers' data prefixes.
	r.client.AnnouncePrefix(ndn.Announcement{
		Name:    r.svsalo.GroupPrefix(),
		Cost:    1000,
		Expose:  true,
		OnError: nil, // TODO
	})

	// If multicast prefix is specified, we need to announce sync prefix separately
	if multicastPrefix != nil {
		r.client.AnnouncePrefix(ndn.Announcement{
			Name:    r.svsalo.SyncPrefix(),
			Cost:    1000,
			Expose:  true,
			OnError: nil, // TODO
		})
	}

	// Start SVS ALO
	if err = r.svsalo.Start(); err != nil {
		return err
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Stops the repository’s SVS service by withdrawing its group and optional multicast prefixes from the NDN client and stopping the underlying SVS ALO component.
func (r *RepoSvs) Stop() (err error) {
	log.Info(r, "Stopping SVS")
	if r.svsalo == nil {
		return nil
	}

	// Withdraw group prefix.
	r.client.WithdrawPrefix(r.svsalo.GroupPrefix(), nil)

	// Withdraw multicast prefix.
	if r.cmd.MulticastPrefix != nil {
		r.client.WithdrawPrefix(r.cmd.MulticastPrefix.Name, nil)
	}

	// Stop SVS ALO
	if err = r.svsalo.Stop(); err != nil {
		return err
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Stores the supplied state as a data packet in the client store under the group name suffixed with the "alo-state" keyword component.
func (r *RepoSvs) commitState(state enc.Wire) {
	name := r.cmd.Group.Name.Append(enc.NewKeywordComponent("alo-state"))
	r.client.Store().Put(name, state.Join())
}

// (AI GENERATED DESCRIPTION): Retrieves the repository group’s stored state wire by appending the “alo-state” component to its name; returns the wire wrapped in `enc.Wire` if present, otherwise returns `nil`.
func (r *RepoSvs) readState() enc.Wire {
	name := r.cmd.Group.Name.Append(enc.NewKeywordComponent("alo-state"))
	if stateWire, _ := r.client.Store().Get(name, false); stateWire != nil {
		return enc.Wire{stateWire}
	}
	return nil
}

// processIncomingPub checks if the given pub is a command for repo.
func (r *RepoSvs) processIncomingPub(w enc.Wire) {
	cmd, err := tlv.ParseRepoCmd(enc.NewWireView(w), false)
	if err != nil {
		// Likely application data.
		return
	}

	if cmd.BlobFetch != nil && cmd.BlobFetch.Name != nil {
		r.processBlobFetch(cmd.BlobFetch.Name.Name)
	} else if cmd.BlobFetch != nil && len(cmd.BlobFetch.Data) > 0 {
		r.processBlobStore(cmd.BlobFetch.Data)
	}
}

// processBlobFetch processes a BlobFetch command.
func (r *RepoSvs) processBlobFetch(name enc.Name) {
	if !r.cmd.Group.Name.IsPrefix(name) {
		log.Warn(r, "Ignoring BlobFetch outside group", "name", name)
		return
	}

	// TODO: retry fetching if failed, even across restarts
	// TODO: do not fetch blobs that are too large
	// TODO: do not fetch blobs that are already stored (though this shouldn't happen)
	r.client.Consume(name, func(status ndn.ConsumeState) {
		if status.Error() != nil {
			log.Warn(r, "BlobFetch error", "err", status.Error(), "name", name)
			return
		}
		log.Info(r, "BlobFetch success", "name", name)
	})
}

// processBlobStore directly stores data from the BlobFetch command.
func (r *RepoSvs) processBlobStore(data [][]byte) {
	for _, w := range data {
		data, _, err := spec.Spec{}.ReadData(enc.NewBufferView(w))
		if err != nil {
			log.Warn(r, "BlobFetch store failed to parse data", "err", err)
			continue
		}
		name := data.Name()

		if !r.cmd.Group.Name.IsPrefix(name) {
			log.Warn(r, "Ignoring BlobFetch store outside group", "name", name)
			continue
		}

		if err := r.client.Store().Put(name, w); err != nil {
			log.Warn(r, "BlobFetch store failed to store data", "err", err)
			continue
		}

		log.Info(r, "BlobFetch store success", "name", name)
	}
}
