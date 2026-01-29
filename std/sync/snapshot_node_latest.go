package sync

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
)

// SnapshotNodeLatest is a snapshot strategy that takes a snapshot of the
// application state whenever a certain number of updates have been made.
//
// Each snapshot is treated as self-contained and replaces any previous
// publications completely. Only the latest (hence the name) snapshot is
// fetched by other nodes, and previous publications are ignored.
//
// When a node bootstraps again, this strategy assumes that the previous
// state is now invalid and fetches the latest snapshot.
type SnapshotNodeLatest struct {
	// Client is the object client.
	Client ndn.Client

	// SnapMe is the callback to get a snapshot of the application state.
	//
	// The state should encode the entire state of the node, and should replace
	// any previous publications completely. If this snapshot is delivered to a
	// node, previous publications will be ignored by the receiving node.
	//
	// The callback is passed the name of the snapshot that will be created.
	SnapMe func(enc.Name) (enc.Wire, error)
	// Threshold is the number of updates before a snapshot is taken.
	Threshold uint64
	// IgnoreValidity ignores validity period in the validation chain
	IgnoreValidity optional.Optional[bool]

	// pss is the struct from the svs layer.
	pss snapPsState
	// prevSeq is my last snapshot sequence number.
	prevSeq uint64
}

// (AI GENERATED DESCRIPTION): Returns the string `"snapshot-node-latest"` as the textual representation of a SnapshotNodeLatest node.
func (s *SnapshotNodeLatest) String() string {
	return "snapshot-node-latest"
}

// (AI GENERATED DESCRIPTION): Returns the SnapshotNodeLatest instance itself as a Snapshot.
func (s *SnapshotNodeLatest) Snapshot() Snapshot {
	return s
}

// initialize the snapshot strategy.
func (s *SnapshotNodeLatest) initialize(pss snapPsState, _ SvMap[svsDataState]) {
	if s.Client == nil || s.SnapMe == nil || s.Threshold == 0 {
		panic("SnapshotNodeLatest: not initialized")
	}
	s.pss = pss
}

// onUpdate determines if a snapshot should be fetched.
func (s *SnapshotNodeLatest) onUpdate(state SvMap[svsDataState], node enc.Name) {
	// We only care about the latest boot.
	// For all other states, make sure the fetch is skipped.
	entries := state[node.TlvStr()]

	for i := range entries {
		if i == len(entries)-1 { // if is last entry
			boot, value := entries[i].Boot, entries[i].Value

			// Check if we should fetch a snapshot
			// 1. Pending gap is more than 2*threshold
			// 2. I have not fetched anything yet
			// And, I'm not already blocked by a fetch
			//
			// TODO: prevent fetching snapshot too fast - throttle this call
			// This will prevent an infinite loop if the snapshot is old (?)
			if value.SnapBlock == 0 && (value.Latest-value.Pending >= s.Threshold*2 || value.Known == 0) {
				entries[i].Value.SnapBlock = 1 // released by fetch callback
				s.fetchSnap(node, boot)
			}
			return
		}

		// Block all older boots permanently
		if entries[i].Value.SnapBlock != -1 {
			entries[i].Value.SnapBlock = -1
			entries[i].Value.Known = entries[i].Value.Latest
			entries[i].Value.Pending = entries[i].Value.Latest
		}
	}
}

// onPublication is called when the state for this node is updated.
func (s *SnapshotNodeLatest) onPublication(state SvMap[svsDataState], pub enc.Name) {
	// This strategy only cares about the latest boot.
	entry := state.Get(s.pss.nodePrefix.TlvStr(), s.pss.bootTime)
	seqNo := entry.Known

	// Check if I should take a snapshot
	// 1. I have reached the threshold
	// 2. I have not taken any snapshot yet
	if seqNo-s.prevSeq >= s.Threshold || (s.prevSeq == 0 && seqNo > 0) {
		s.takeSnap(seqNo)
	}
}

// snapName is the naming convention for snapshots.
func (s *SnapshotNodeLatest) snapName(node enc.Name, boot uint64) enc.Name {
	return s.pss.groupPrefix.
		Append(node...).
		Append(enc.NewTimestampComponent(boot)).
		Append(enc.NewKeywordComponent("SNAP"))
}

// fetchSnap fetches the latest snapshot for a remote node.
func (s *SnapshotNodeLatest) fetchSnap(node enc.Name, boot uint64) {
	// Discover the latest snapshot
	s.Client.ConsumeExt(ndn.ConsumeExtArgs{
		Name:           s.snapName(node, boot),
		IgnoreValidity: s.IgnoreValidity,
		Callback: func(cstate ndn.ConsumeState) {
			if cstate.Error() != nil {
				// Do not try too fast in case NFD returns NACK
				time.AfterFunc(2*time.Second, func() {
					s.handleSnap(node, boot, cstate)
				})
			} else {
				s.handleSnap(node, boot, cstate)
			}
		},
	})
}

// handleSnap processes the fetched snapshot.
func (s *SnapshotNodeLatest) handleSnap(node enc.Name, boot uint64, cstate ndn.ConsumeState) {
	s.pss.onSnap(func(state SvMap[svsDataState]) (pub SvsPub, err error) {
		hash := node.TlvStr()
		entry := state.Get(hash, boot)

		// SnapBlock could change if a new boot is detected
		if entry.SnapBlock != 1 {
			return pub, fmt.Errorf("fetched blocked snapshot - ignoring")
		}

		// Check for fetching errors
		err = cstate.Error()

		// Check if the snapshot is still current
		if err == nil && entry.Known >= cstate.Version() {
			err = fmt.Errorf("fetched old snapshot - ignoring")
		}

		if err != nil {
			entry.SnapBlock = 0
			state.Set(hash, boot, entry)
			return pub, &ErrSync{
				Publisher: node,
				BootTime:  boot,
				Err:       fmt.Errorf("%w: %w", ErrSnapshot, err),
			}
		}

		// Update the state vector
		entry.SnapBlock = 0
		entry.Known = cstate.Version()
		entry.Pending = max(entry.Pending, entry.Known)
		state.Set(hash, boot, entry)

		return SvsPub{
			Publisher:  node,
			Content:    cstate.Content(),
			DataName:   cstate.Name(),
			BootTime:   boot,
			SeqNum:     cstate.Version(),
			IsSnapshot: true,
		}, nil
	})
}

// takeSnap takes a snapshot of the application state for the current node.
func (s *SnapshotNodeLatest) takeSnap(seqNo uint64) {
	basename := s.snapName(s.pss.nodePrefix, s.pss.bootTime)
	name := basename.WithVersion(seqNo)

	// Request snapshot from application
	wire, err := s.SnapMe(name)
	if err != nil {
		log.Error(s, "Failed to get snapshot", "err", err)
		return
	}

	// Get previous snapshot name to evict later
	prevName, err := s.Client.LatestLocal(basename)
	if err != nil {
		log.Warn(s, "Failed to get previous snapshot", "err", err)
	}

	// Publish snapshot into our store
	_, err = s.Client.Produce(ndn.ProduceArgs{
		Name:    name,
		Content: wire,
	})
	if err != nil {
		log.Error(s, "Failed to publish snapshot", "err", err, "name", name)
		return
	}

	// Update the sequence number
	s.prevSeq = seqNo

	// Evict previous snapshot
	if prevName != nil {
		if err := s.Client.Remove(prevName); err != nil {
			log.Warn(s, "Failed to remove previous snapshot", "err", err)
		}
	}

	// Evict covered publications from 0 to seqNo-3*threshold
	if seqNo >= 4*s.Threshold {
		// No version specified - this will remove metadata too
		if err := s.Client.Store().RemoveFlatRange(
			s.pss.groupPrefix.
				Append(s.pss.nodePrefix...).
				Append(enc.NewTimestampComponent(s.pss.bootTime)),
			enc.NewSequenceNumComponent(0),
			enc.NewSequenceNumComponent(seqNo-3*s.Threshold),
		); err != nil {
			log.Warn(s, "Failed to evict old publications from store", "err", err)
		}
	}
}
