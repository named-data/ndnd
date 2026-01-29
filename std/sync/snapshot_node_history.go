package sync

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/ndn/svs_ps"
	"github.com/named-data/ndnd/std/types/optional"
)

const SnapHistoryIndexFreshness = time.Millisecond * 10

// SnapshotNodeLatest is a snapshot strategy that assumes that it is not
// possible to take a snapshot of the application state. Instead, it creates
// a snapshot of the entire publication history.
//
// This strategy should be used with highly persistent storage, as it will
// store all publications since the node bootstrapped, and fetch publications
// from a node's previous instances (bootstraps). To ensure that publications
// from previous instances are available, the application must use NDN Repo.
type SnapshotNodeHistory struct {
	// Client is the object client.
	Client ndn.Client
	// Threshold is the number of updates before a snapshot is taken.
	Threshold uint64

	// Compress is the optional callback to compress the history snapshot.
	//
	// 1. The snapshot should be compressed in place.
	// 2. If grouping is used, the last sequence number of a group should be kept.
	//    Earlier sequence numbers can then be removed.
	// 3. #2 implies that the last sequence number cannot be removed.
	//
	// For example, for snapshot 1, [2, 3, 4], (5), 6, (7), 8, 9, 10:
	//  - [VALID] 1, [234], 6, (57), 8, 10
	//  - [INVALID] 1, 4[234], 6, 7(57), 8, 9, 10
	//  - [INVALID] 1, 3[234], 6, 7(57), 8, 9, 10
	//  - [INVALID] 1, 4[234], 5(57), 6, 8, 9, 10
	//  - [INVALID] 1, 4[234], 6, 8, 9, 10
	Compress func(*svs_ps.HistorySnap)

	// In Repo mode, all snapshots are fetched automtically for persistence.
	IsRepo bool
	// IgnoreValidity ignores validity period in the validation chain
	IgnoreValidity optional.Optional[bool]
	// repoKnown is the known snapshot sequence number.
	repoKnown SvMap[uint64]

	// pss is the struct from the svs layer.
	pss snapPsState
	// prevSeq is my last snapshot sequence number.
	prevSeq uint64
}

// (AI GENERATED DESCRIPTION): Returns the fixed string `"snapshot-node-history"` as the textual representation of a SnapshotNodeHistory value.
func (s *SnapshotNodeHistory) String() string {
	return "snapshot-node-history"
}

// (AI GENERATED DESCRIPTION): Returns the `SnapshotNodeHistory` instance as a `Snapshot`.
func (s *SnapshotNodeHistory) Snapshot() Snapshot {
	return s
}

// initialize the snapshot strategy.
func (s *SnapshotNodeHistory) initialize(pss snapPsState, state SvMap[svsDataState]) {
	if s.Client == nil || s.Threshold == 0 {
		panic("SnapshotNodeLatest: not initialized")
	}
	s.pss = pss

	// Load repo known state for repo mode
	if s.IsRepo {
		s.repoKnown = make(SvMap[uint64])
		for hash, vals := range state {
			for _, val := range vals {
				// Fetch one threshold again if needed to be safe
				rk := uint64(0)
				if val.Value.Known > s.Threshold {
					rk = val.Value.Known - s.Threshold
				}
				s.repoKnown.Set(hash, val.Boot, rk)
			}
		}
	}
}

// onUpdate determines if a snapshot should be fetched.
func (s *SnapshotNodeHistory) onUpdate(state SvMap[svsDataState], node enc.Name) {
	nodeHash := node.TlvStr()
	entries := state[nodeHash]

	for i := range entries {
		boot, value := entries[i].Boot, entries[i].Value // copies

		// Nothing to do
		if value.Pending >= value.Latest {
			continue
		}

		// Skip this instance, what's the point?
		if node.Equal(s.pss.nodePrefix) && boot == s.pss.bootTime {
			continue
		}

		// Threshold to fetch the snapshot
		fetchThreshold := s.Threshold * 2

		// Repo mode - fetch all snapshots
		if value.SnapBlock == 0 && s.IsRepo {
			rk := s.repoKnown.Get(nodeHash, boot)
			value.Pending = rk
			value.Known = rk
			fetchThreshold = s.Threshold + 1
		}

		// Check if we should fetch a snapshot
		//
		// TODO: prevent fetching snapshot too fast - throttle this call
		// This will prevent an infinite loop if the snapshot is old (?)
		if value.SnapBlock == 0 && (value.Latest-value.Pending >= fetchThreshold || value.Known == 0) {
			entries[i].Value.SnapBlock = 1 // released by fetch callback
			s.fetchIndex(node, boot, value.Known)
			continue
		}
	}
}

// onPublication is called when the state for this node is updated.
func (s *SnapshotNodeHistory) onPublication(state SvMap[svsDataState], pub enc.Name) {
	// Get the sequence number
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
func (s *SnapshotNodeHistory) snapName(node enc.Name, boot uint64) enc.Name {
	return s.pss.groupPrefix.
		Append(node...).
		Append(enc.NewTimestampComponent(boot)).
		Append(enc.NewKeywordComponent("HIST"))
}

// (AI GENERATED DESCRIPTION): Constructs the name for a node’s history index by appending the node’s name, the boot‑time timestamp, and the keyword “HIDX” to the group prefix.
func (s *SnapshotNodeHistory) idxName(node enc.Name, boot uint64) enc.Name {
	return s.pss.groupPrefix.
		Append(node...).
		Append(enc.NewTimestampComponent(boot)).
		Append(enc.NewKeywordComponent("HIDX"))
}

// fetchIndex fetches the latest index for a remote node.
func (s *SnapshotNodeHistory) fetchIndex(node enc.Name, boot uint64, known uint64) {
	s.Client.ConsumeExt(ndn.ConsumeExtArgs{
		Name:           s.idxName(node, boot),
		IgnoreValidity: s.IgnoreValidity,
		Callback: func(cstate ndn.ConsumeState) {
			go s.handleIndex(node, boot, known, cstate)
		},
	})
}

// handleIndex processes the fetched index.
func (s *SnapshotNodeHistory) handleIndex(node enc.Name, boot uint64, known uint64, cstate ndn.ConsumeState) {
	hash := node.TlvStr()

	onError := func(err error) {
		time.Sleep(2 * time.Second) // we are in a different goroutine

		s.pss.onSnap(func(state SvMap[svsDataState]) (SvsPub, error) {
			entry := state.Get(hash, boot)
			entry.SnapBlock = 0
			state.Set(hash, boot, entry)

			return SvsPub{}, &ErrSync{
				Publisher: node,
				BootTime:  boot,
				Err:       err,
			}
		})
	}

	// Fetching error. We already debounced in the fetchIndex callback.
	if err := cstate.Error(); err != nil {
		onError(fmt.Errorf("failed to fetch snapshot index: %w", err))
		return
	}

	// Parse the index
	index, err := svs_ps.ParseHistoryIndex(enc.NewWireView(cstate.Content()), true)
	if err != nil {
		onError(fmt.Errorf("failed to parse snapshot index: %w", err))
		return
	}

	// Fetch one snapshot at a time under this goroutine
	for _, seqNo := range index.SeqNos {
		if seqNo > known {
			snapC := make(chan ndn.ConsumeState)

			snapName := s.snapName(node, boot).WithVersion(seqNo)
			s.Client.ConsumeExt(ndn.ConsumeExtArgs{
				Name:           snapName,
				IgnoreValidity: s.IgnoreValidity,
				Callback:       func(cstate ndn.ConsumeState) { snapC <- cstate },
			})

			scstate := <-snapC
			if err := scstate.Error(); err != nil {
				onError(fmt.Errorf("failed to fetch snapshot: %w", err))
				return
			}

			// Parse history
			snapshot, err := svs_ps.ParseHistorySnap(enc.NewWireView(scstate.Content()), true)
			if err != nil {
				onError(fmt.Errorf("failed to parse snapshot: %w", err))
				return
			}

			// Verify snapshot has entries till the end
			ssVersion := scstate.Version()
			if len(snapshot.Entries) == 0 || snapshot.Entries[len(snapshot.Entries)-1].SeqNo != ssVersion {
				onError(fmt.Errorf("fetched invalid snapshot - ignoring"))
				return
			}

			s.pss.onSnap(func(state SvMap[svsDataState]) (SvsPub, error) {
				// do not use onError in the callback (blocking sleep)
				entry := state.Get(hash, boot)

				// Filter out any publications which are already known
				for len(snapshot.Entries) > 0 {
					if snapshot.Entries[0].SeqNo <= entry.Known {
						snapshot.Entries = snapshot.Entries[1:]
					} else {
						break
					}
				}

				// In repo mode, we fetch the snapshot even if it is new,
				// in this case do not deliver the fetched snapshot since it
				// will prevent fetching the other updates.
				if s.IsRepo {
					s.repoKnown.Set(hash, boot, ssVersion)
					if entry.Latest <= ssVersion+2*s.Threshold {
						return SvsPub{}, nil
					}
				}

				// Check if snapshot is outdated
				if entry.Known >= ssVersion {
					return SvsPub{}, nil
				}

				// Update the state vector
				entry.Known = ssVersion
				entry.Pending = max(entry.Pending, entry.Known)
				state.Set(hash, boot, entry)

				return SvsPub{
					Publisher:  node,
					Content:    snapshot.Encode(),
					DataName:   scstate.Name(),
					BootTime:   boot,
					SeqNum:     scstate.Version(),
					IsSnapshot: true,
				}, nil
			})
		}
	}

	// Wait for the freshness period of the index before giving back control.
	// This ensure we don't fetch the same index again.
	time.Sleep(SnapHistoryIndexFreshness)

	// Reset snap block flag
	s.pss.onSnap(func(state SvMap[svsDataState]) (SvsPub, error) {
		entry := state.Get(hash, boot)
		entry.SnapBlock = 0
		state.Set(hash, boot, entry)
		return SvsPub{}, nil
	})
}

// takeSnap takes a snapshot of the application state for the current node.
func (s *SnapshotNodeHistory) takeSnap(seqNo uint64) {
	// Current snapshot index
	prevIndexName, index, err := s.getIndex()
	if err != nil {
		log.Debug(s, "Failed to get previous index, starting fresh", "err", err)
	}
	if index == nil {
		index = &svs_ps.HistoryIndex{}
	}

	// Check version number of previous snapshot
	if len(index.SeqNos) > 0 {
		s.prevSeq = index.SeqNos[len(index.SeqNos)-1]
	}
	if s.prevSeq > 0 && seqNo < s.prevSeq+s.Threshold-1 {
		log.Debug(s, "Previous snapshot is still current", "prev", s.prevSeq, "seq", seqNo)
		return
	}

	// Add new sequence number to the index
	index.SeqNos = append(index.SeqNos, seqNo)

	// Create a new snapshot
	snapshot := &svs_ps.HistorySnap{
		Entries: make([]*svs_ps.HistorySnapEntry, 0, seqNo-s.prevSeq),
	}

	// Add all publications since the last snapshot
	pubBasename := s.pss.groupPrefix.
		Append(s.pss.nodePrefix...).
		Append(enc.NewTimestampComponent(s.pss.bootTime))
	for i := s.prevSeq + 1; i <= seqNo; i++ {
		pubName := pubBasename.
			Append(enc.NewSequenceNumComponent(i)).
			WithVersion(enc.VersionImmutable)
		content, err := s.Client.GetLocal(pubName)
		if err != nil {
			log.Error(s, "Failed to get publication", "err", err, "name", pubName)
			return
		}
		snapshot.Entries = append(snapshot.Entries, &svs_ps.HistorySnapEntry{
			SeqNo:   i,
			Content: content,
		})
	}

	// Compress the snapshot
	if s.Compress != nil {
		s.Compress(snapshot)
	}

	// Publish snapshot into our store
	snapName := s.snapName(s.pss.nodePrefix, s.pss.bootTime).
		WithVersion(seqNo)
	_, err = s.Client.Produce(ndn.ProduceArgs{
		Name:    snapName,
		Content: snapshot.Encode(),
	})
	if err != nil {
		log.Error(s, "Failed to publish snapshot", "err", err, "name", snapName)
		return
	}

	// Write new index
	indexWire := index.Encode()
	_, err = s.Client.Produce(ndn.ProduceArgs{
		Name: s.idxName(s.pss.nodePrefix, s.pss.bootTime).
			WithVersion(seqNo),
		Content:         indexWire,
		FreshnessPeriod: SnapHistoryIndexFreshness,
	})
	if err != nil {
		log.Error(s, "Failed to publish index", "err", err, "name", prevIndexName)
		return
	}

	// Update the sequence number
	s.prevSeq = seqNo

	// Evict old index
	if prevIndexName != nil {
		err = s.Client.Remove(prevIndexName)
		if err != nil {
			log.Warn(s, "Failed to evict old index", "err", err, "name", prevIndexName)
		}
	}

	// Evict publications more than 3 snapshots old
	if len(index.SeqNos) > 4 {
		evictLast := index.SeqNos[len(index.SeqNos)-3]
		err = s.Client.Store().RemoveFlatRange(
			pubBasename,
			enc.NewSequenceNumComponent(0),
			enc.NewSequenceNumComponent(evictLast),
		)
		if err != nil {
			log.Warn(s, "Failed to evict old publications", "err", err)
		}
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the most recent locally stored snapshot history index for the node, parses its wire representation, and returns the index name and parsed HistoryIndex.
func (s *SnapshotNodeHistory) getIndex() (enc.Name, *svs_ps.HistoryIndex, error) {
	idxName := s.idxName(s.pss.nodePrefix, s.pss.bootTime)

	prevIdxName, err := s.Client.LatestLocal(idxName)
	if err != nil {
		return nil, nil, err
	}

	prevIdxWire, err := s.Client.GetLocal(prevIdxName)
	if err != nil {
		return nil, nil, err
	}

	prevIdx, err := svs_ps.ParseHistoryIndex(enc.NewWireView(prevIdxWire), true)
	if err != nil {
		return nil, nil, err
	}

	return prevIdxName, prevIdx, nil
}
