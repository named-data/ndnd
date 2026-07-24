package sync

import (
	"cmp"
	"math/rand/v2"
	"slices"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
)

// syncSendReason distinguishes why a Sync Interest is being sent.
type syncSendReason int

const (
	syncSendOther syncSendReason = iota
	syncSendPublication
	syncSendPeriodic
	syncSendRecovery
)

// PartialEncodeOpts configures subset selection for inline PARTIAL vectors.
type PartialEncodeOpts struct {
	Sender      enc.Name
	Threshold   int
	Repair      []enc.Name
	Propagation []enc.Name
	Mtime       map[string]time.Time
}

// svsSendInput carries everything needed to build inline Sync Data for send.
type svsSendInput struct {
	State       SvMap[uint64]
	Reason      syncSendReason
	Threshold   int
	Sender      enc.Name
	Repair      []enc.Name
	Propagation []enc.Name
	Mtime       map[string]time.Time
}

// buildSvsDataForSend picks embedded FULL or PARTIAL SvsData for an outgoing
// Sync message. Returns nil when publication-triggered PARTIAL encoding cannot
// fit even the sender-only baseline (signaled by an empty StateVector from
// encodePartialStateVector): the caller MUST fall back to publish+pull
// (see shouldUsePublishPull). Other reasons always return a non-nil result.
func buildSvsDataForSend(in svsSendInput) *spec_svs.SvsData {
	fullSv := in.State.Encode(func(seq uint64) uint64 { return seq })
	fullData := &spec_svs.SvsData{
		MemberSetHash:   ComputeMembershipHash(in.State),
		FullStateVector: &spec_svs.FullStateVector{StateVector: fullSv},
	}

	if in.Reason != syncSendPublication || len(fullData.Encode().Join()) <= in.Threshold {
		return fullData
	}

	partialSv := encodePartialStateVector(in.State, PartialEncodeOpts{
		Sender:      in.Sender,
		Threshold:   in.Threshold,
		Repair:      in.Repair,
		Propagation: in.Propagation,
		Mtime:       in.Mtime,
	})
	if len(partialSv.Entries) == 0 {
		// Baseline exceeded Threshold; caller must use publish+pull.
		return nil
	}
	return &spec_svs.SvsData{
		MemberSetHash:      ComputeMembershipHash(in.State),
		PartialStateVector: &spec_svs.PartialStateVector{StateVector: partialSv},
	}
}

// encodePartialStateVector builds a PARTIAL StateVector for new publication.
// Entry [0] is the sender; entries [1..n] are in NDN canonical order.
//
// Returns an empty StateVector (no entries) if the sender-only baseline
// itself exceeds Threshold: the caller MUST fall back to publish+pull in
// that case and the empty vector is the explicit signal that no PARTIAL
// body could be fit under the size budget.
func encodePartialStateVector(state SvMap[uint64], opts PartialEncodeOpts) *spec_svs.StateVector {
	seq := func(v uint64) uint64 { return v }
	senderHash := opts.Sender.TlvStr()

	senderEntry := state.encodeNameEntry(opts.Sender, seq)
	if senderEntry == nil {
		senderEntry = &spec_svs.StateVectorEntry{Name: opts.Sender}
	}

	// Sender-only baseline must always fit when possible.
	baseline := &spec_svs.StateVector{Entries: []*spec_svs.StateVectorEntry{senderEntry}}
	baselineData := &spec_svs.SvsData{
		MemberSetHash:      ComputeMembershipHash(state),
		PartialStateVector: &spec_svs.PartialStateVector{StateVector: baseline},
	}
	if len(baselineData.Encode().Join()) > opts.Threshold {
		// Baseline too large to fit even the sender entry: return an
		// empty PARTIAL so the caller can detect the overflow and fall
		// back to publish+pull.
		return &spec_svs.StateVector{}
	}

	peers := priorityOrderedPeers(state, senderHash, opts)
	included := map[string]bool{senderHash: true}
	entries := []*spec_svs.StateVectorEntry{senderEntry}

	for _, name := range peers {
		hash := name.TlvStr()
		if included[hash] {
			continue
		}
		entry := state.encodeNameEntry(name, seq)
		if entry == nil {
			continue
		}

		trial := append(slices.Clone(entries), entry)
		sortPartialTail(trial)
		trialSv := &spec_svs.StateVector{Entries: trial}
		trialData := &spec_svs.SvsData{
			MemberSetHash:      ComputeMembershipHash(state),
			PartialStateVector: &spec_svs.PartialStateVector{StateVector: trialSv},
		}
		if len(trialData.Encode().Join()) > opts.Threshold {
			break
		}

		entries = trial
		included[hash] = true
	}

	// entries is already sorted tail-wise: the loop's sortPartialTail(trial)
	// runs on every accepted iteration, so the trailing sort is redundant.
	return &spec_svs.StateVector{Entries: entries}
}

// priorityOrderedPeers returns the producer names that consumers should
// consider for inclusion in a new-publication PARTIAL StateVector, ordered
// by inclusion priority. The caller iterates the returned slice and
// greedily adds entries until the size budget is reached.
//
// The priority order is:
//
//  1. Repair targets from the suppression-merge state (newest entries first).
//  2. Propagation targets (the most recently updated producers).
//  3. Inactive producers (zero-value entries) in randomized order — these
//     are included only when bandwidth allows, so randomization is fair.
//  4. Remaining active producers, sorted by (a) recency descending then
//     (b) canonical NDN name ascending.
//
// The sender is excluded — it is always included at entries[0].
func priorityOrderedPeers(state SvMap[uint64], senderHash string, opts PartialEncodeOpts) []enc.Name {
	seen := map[string]bool{senderHash: true}
	out := make([]enc.Name, 0, len(state))

	appendUnique := func(names []enc.Name) {
		for _, name := range names {
			hash := name.TlvStr()
			if seen[hash] {
				continue
			}
			if _, ok := state[hash]; !ok {
				continue
			}
			seen[hash] = true
			out = append(out, name)
		}
	}

	appendUnique(opts.Repair)
	appendUnique(opts.Propagation)

	inactive := make([]enc.Name, 0)
	remaining := make([]enc.Name, 0)
	for name, vals := range state.Iter() {
		hash := name.TlvStr()
		if seen[hash] {
			continue
		}
		if isInactiveProducer(vals) {
			inactive = append(inactive, name)
			continue
		}
		remaining = append(remaining, name)
	}

	rand.Shuffle(len(inactive), func(i, j int) {
		inactive[i], inactive[j] = inactive[j], inactive[i]
	})
	appendUnique(inactive)

	// Sort by (recency desc, canonical name asc) using a single comparator.
	// slices.SortFunc is not stable, so sorting twice is not a reliable
	// tie-breaker for entries with equal recency scores.
	slices.SortFunc(remaining, func(a, b enc.Name) int {
		if c := cmp.Compare(recencyScore(opts.Mtime, b), recencyScore(opts.Mtime, a)); c != 0 {
			return c
		}
		return a.Compare(b)
	})
	appendUnique(remaining)

	return out
}

func isInactiveProducer(vals []SvMapVal[uint64]) bool {
	for _, val := range vals {
		if val.Value > 0 {
			return false
		}
	}
	return true
}

func recencyScore(mtime map[string]time.Time, name enc.Name) int64 {
	if mtime == nil {
		return 0
	}
	t, ok := mtime[name.TlvStr()]
	if !ok {
		return 0
	}
	return t.UnixNano()
}

// sortPartialTail keeps the first entry fixed (the sender) and sorts the
// remaining entries in canonical NDN name order. PARTIAL vectors place the
// sender at entries[0] and the rest must be canonically ordered for byte-
// deterministic encoding.
func sortPartialTail(entries []*spec_svs.StateVectorEntry) {
	if len(entries) <= 1 {
		return
	}
	slices.SortFunc(entries[1:], func(a, b *spec_svs.StateVectorEntry) int {
		return a.Name.Compare(b.Name)
	})
}

// encodeNameEntry encodes one producer name from the map.
func (m SvMap[V]) encodeNameEntry(name enc.Name, seq func(V) uint64) *spec_svs.StateVectorEntry {
	hash := name.TlvStr()
	vals, ok := m[hash]
	if !ok {
		return nil
	}

	entry := &spec_svs.StateVectorEntry{
		Name:         name,
		SeqNoEntries: make([]*spec_svs.SeqNoEntry, 0, len(vals)),
	}
	for _, val := range vals {
		if seqNo := seq(val.Value); seqNo > 0 {
			entry.SeqNoEntries = append(entry.SeqNoEntries, &spec_svs.SeqNoEntry{
				BootstrapTime: val.Boot,
				SeqNo:         seqNo,
			})
		}
	}
	return entry
}
