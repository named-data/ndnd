package sync

import (
	"slices"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

type svsDataState struct {
	// Known is the fetched sequence number.
	// Data is handed off to outgoing pipe.
	Known uint64
	// Latest is the latest sequence number.
	// (Latest-Pending) is not in the pipeline.
	Latest uint64
	// Pending is the pending sequence number.
	// (Pending-Known) has outstanding Interests.
	Pending uint64
	// PendingPubs is the fetched data not yet delivered.
	PendingPubs map[uint64]SvsPub
	// SnapBlock is the snapshot block flag.
	// If non-zero, fetching is blocked.
	SnapBlock int
}

// (AI GENERATED DESCRIPTION): Builds the full name for a data object by appending the node identifier, boot‑timestamp, and sequence number to the group’s prefix and marking the resulting name as immutable.
func (s *SvsALO) objectName(node enc.Name, boot uint64, seq uint64) enc.Name {
	return s.GroupPrefix().
		Append(node...).
		Append(enc.NewTimestampComponent(boot)).
		Append(enc.NewSequenceNumComponent(seq)).
		WithVersion(enc.VersionImmutable)
}

// (AI GENERATED DESCRIPTION): Publishes a new Data object with the supplied content, updates the SVS state vector and snapshot strategy, and returns the produced name and the instance’s serialized state.
func (s *SvsALO) produceObject(content enc.Wire) (enc.Name, enc.Wire, error) {
	// This instance owns the underlying SVS instance.
	// So we can be sure that the sequence number does not
	// change while we hold the lock on this instance.
	node := s.opts.Name
	boot := s.svs.GetBootTime()
	seq := s.svs.GetSeqNo(node) + 1

	name, err := s.client.Produce(ndn.ProduceArgs{
		Name:    s.objectName(node, boot, seq),
		Content: content,
	})
	if err != nil {
		return nil, nil, err
	}

	// We don't get notified of changes to our own state.
	// So we need to update the state vector ourselves.
	s.state.Set(node.TlvStr(), boot, svsDataState{
		Known:   seq,
		Latest:  seq,
		Pending: seq,
	})

	// Notify the snapshot strategy
	s.opts.Snapshot.onPublication(s.state, name)

	// Update the state vector
	if got := s.svs.IncrSeqNo(node); got != seq {
		panic("[BUG] sequence number mismatch - who changed it?")
	}

	return name, s.instanceState(), nil
}

// consumeCheck looks for new objects to fetch and queues them.
func (s *SvsALO) consumeCheck(node enc.Name) {
	if !s.nodePs.HasSub(node) {
		return
	}

	// Check with the snapshot strategy
	s.opts.Snapshot.onUpdate(s.state, node)

	hash := node.TlvStr()
	totalPending := uint64(0)

	for _, entry := range s.state[hash] {
		fstate := entry.Value
		totalPending += fstate.Pending - fstate.Known
		if fstate.SnapBlock != 0 {
			continue
		}

		// Check if there is something to fetch
		for fstate.Pending < fstate.Latest {
			// Too many pending interests
			if totalPending > s.opts.MaxPipelineSize {
				return
			}

			// Skip fetching if the client is congested and there are
			// at least two pending fetches for this producer.
			if totalPending >= 2 && s.client.IsCongested() {
				return
			}

			// Queue the fetch
			totalPending++
			fstate.Pending++
			s.state.Set(hash, entry.Boot, fstate)
			s.consumeObject(node, entry.Boot, fstate.Pending)
		}
	}
}

// consumeObject fetches a single object from the network.
// The callback puts data on the outgoing pipeline and re-calls
// check to fetch more objects if necessary.
func (s *SvsALO) consumeObject(node enc.Name, boot uint64, seq uint64) {
	fetchName := s.objectName(node, boot, seq)
	s.client.ConsumeExt(ndn.ConsumeExtArgs{
		Name: fetchName,
		// inherit ignoreValidity from SVS, not correct but practical
		IgnoreValidity: s.opts.Svs.IgnoreValidity,
		Callback: func(status ndn.ConsumeState) {
			s.mutex.Lock()
			defer s.mutex.Unlock()

			// Always check if we can fetch more
			defer s.consumeCheck(node)

			// Get the state vector entry
			hash := node.TlvStr()
			entry := s.state.Get(hash, boot)

			// Check if this is already delivered
			if seq <= entry.Known {
				return
			}

			// Get the list of subscribers
			subscribers := slices.Collect(s.nodePs.Subs(node))

			// Check if we have to deliver this data
			if entry.SnapBlock != 0 || len(subscribers) == 0 {
				entry.Pending = min(entry.Pending, seq-1)
				s.state.Set(hash, boot, entry)
				return
			}

			// Check for errors
			if err := status.Error(); err != nil {
				// Propagate the error to application
				s.queueError(&ErrSync{
					Publisher: node,
					BootTime:  boot,
					Err:       err,
				})

				// TODO: exponential backoff
				time.AfterFunc(2*time.Second, func() {
					s.consumeObject(node, boot, seq)
				})
				return
			}

			// Initialize the pending map
			if entry.PendingPubs == nil {
				entry.PendingPubs = make(map[uint64]SvsPub)
				s.state.Set(hash, boot, entry)
			}

			// Store the content for in-order delivery
			// The size of this map is upper bounded
			entry.PendingPubs[seq] = SvsPub{
				Publisher: node,
				Content:   status.Content(),
				DataName:  status.Name(),
				BootTime:  boot,
				SeqNum:    seq,
			}

			for {
				// Check if the next seq is available
				nextSeq := entry.Known + 1
				pub, ok := entry.PendingPubs[nextSeq]
				if !ok {
					break
				}

				// Update known state
				entry.Known = nextSeq
				delete(entry.PendingPubs, nextSeq)
				s.state.Set(hash, boot, entry)

				// Deliver the data to application
				pub.subcribers = subscribers // use most current list
				s.queuePub(pub)
			}
		},
	})
}

// snapRecvCallback is called by the snapshot strategy to indicate
// that a snapshot has been fetched.
func (s *SvsALO) snapRecvCallback(callback snapRecvCallback) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Trigger fetch for all publishers even if the callback fails
	defer func() {
		for name := range s.state.Iter() {
			s.consumeCheck(name)
		}
	}()

	// Get the snapshot under the lock, and let the strategy
	// mutate the state safely.
	pub, err := callback(s.state)
	if err != nil {
		s.queueError(err)
		return
	}
	if pub.Content == nil {
		// no error but ignore the snapshot
		return
	}

	// Send the snapshot to the application
	s.queuePub(pub)
}

// queuePub queues a publication to the application.
func (s *SvsALO) queuePub(pub SvsPub) {
	if pub.subcribers == nil {
		pub.subcribers = slices.Collect(s.nodePs.Subs(pub.Publisher))
	}

	if pub.State == nil {
		pub.State = s.instanceState()
	}

	s.outpipe <- pub
}

// queueError queues an error to the application.
func (s *SvsALO) queueError(err error) {
	select {
	case s.errpipe <- err:
	default:
	}
}
