package sync

import (
	"bytes"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
	"github.com/named-data/ndnd/std/types/optional"
)

const (
	syncDataKeyword   = "svs"
	fullVectorKeyword = "sv"
)

// deriveFullVectorPrefix maps SyncDataName (.../32=svs) to the published full-vector prefix (.../32=sv).
func deriveFullVectorPrefix(syncDataName enc.Name) enc.Name {
	if len(syncDataName) == 0 {
		return nil
	}
	base := syncDataName
	if base.At(-1).IsKeyword(syncDataKeyword) {
		base = base.Prefix(-1)
	}
	return base.Append(enc.NewKeywordComponent(fullVectorKeyword))
}

// resolveFullVectorPrefix returns the explicit FullVectorPrefix if set,
// otherwise derives it from SyncDataName.
func resolveFullVectorPrefix(explicit, syncDataName enc.Name) enc.Name {
	if len(explicit) > 0 {
		return explicit.Clone()
	}
	return deriveFullVectorPrefix(syncDataName)
}

// pullRefFromSyncDataWire returns the trust prefix for fetching a publish-only
// SvsDataRef. The "ref" field of Sync Data is the published full-vector name
// (.../32=sv/<version>); the trust prefix is the same name with the version
// component stripped, which corresponds to the sender's .../32=sv prefix used
// for all its published full vectors and is what an authorized consumer must
// trust to follow the reference.
func pullRefFromSyncDataWire(dataWire enc.Wire) enc.Name {
	data, _, err := spec.Spec{}.ReadData(enc.NewWireView(dataWire))
	if err != nil {
		return nil
	}
	name := data.Name()
	if len(name) == 0 {
		return nil
	}
	if name.At(-1).IsVersion() {
		name = name.Prefix(-1)
	}
	return deriveFullVectorPrefix(name)
}

func buildAnnounceSvsData(state SvMap[uint64], ref enc.Name) *spec_svs.SvsData {
	return &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(state),
		SvsDataRef:    ref,
	}
}

// shouldUseAnnouncePull reports whether the sender should publish at .../32=sv
// and emit publish-only Sync Data (mhash + SvsDataRef, no embedded vector)
// instead of an embedded FULL or PARTIAL StateVector.
func shouldUseAnnouncePull(reason syncSendReason, threshold int, state SvMap[uint64]) bool {
	if reason == syncSendRecovery {
		return true
	}
	if reason == syncSendPublication {
		return false
	}
	sv := state.Encode(func(seq uint64) uint64 { return seq })
	full := &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(state),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   sv,
	}
	return len(full.Encode().Join()) > threshold
}

// publishFullVectorData produces retrievable inline FULL SvsData at .../32=sv/<version>.
func (s *SvSync) publishFullVectorData(state SvMap[uint64]) (enc.Name, error) {
	if len(s.fullVectorPrefix) == 0 {
		return nil, fmt.Errorf("full vector prefix unset")
	}
	sv := state.Encode(func(seq uint64) uint64 { return seq })
	content := (&spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(state),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   sv,
	}).Encode()
	name := s.fullVectorPrefix.WithVersion(enc.VersionUnixMicro)
	return s.o.Client.Produce(ndn.ProduceArgs{
		Name:    name,
		Content: content,
	})
}

// pullFullVectorMinInterval debounces pullFullVector per sender. During convergence on a
// large group, every sync that crosses the membership hash boundary schedules a pull; without
// gating, a node can accumulate redundant segment-0 fetches for the same content, which
// exhausts retry budgets under network load. We allow at most one pull per sender per
// pullFullVectorMinInterval.
const pullFullVectorMinInterval = 5 * time.Second

// pullFullVector fetches a published full State Vector and merges it on the main loop.
// trustPrefix is the sender's .../32=sv prefix; ref must be equal to or below it.
//
// [Impl] The 5s per-sender debounce (pullFullVectorMinInterval) is an
// implementation detail documented in §5.6 of the v4 spec: it limits the
// fan-in when many peers cross an mhash boundary at the same time and is
// safe to relax provided the consumer's retry budget scales accordingly.
func (s *SvSync) pullFullVector(ref enc.Name, trustPrefix enc.Name) {
	if len(ref) == 0 {
		return
	}
	if !isTrustedSvsDataRef(ref, trustPrefix) {
		log.Warn(s, "pullFullVector rejected untrusted SvsDataRef", "ref", ref, "trust", trustPrefix)
		return
	}

	// Debounce per sender: drop the pull if one is already in flight or completed recently.
	senderHash := trustPrefix.TlvStr()
	s.mutex.Lock()
	if last, ok := s.lastPullTime[senderHash]; ok && time.Since(last) < pullFullVectorMinInterval {
		s.mutex.Unlock()
		return
	}
	s.lastPullTime[senderHash] = time.Now()
	s.mutex.Unlock()

	s.o.Client.ConsumeExt(ndn.ConsumeExtArgs{
		Name:             ref.Clone(),
		TryStore:         true,
		NoMetadata:       true,
		UseSignatureTime: s.o.UseSignatureTime,
		IgnoreValidity:   s.o.IgnoreValidity,
		Callback: func(st ndn.ConsumeState) {
			if st.Error() != nil {
				log.Warn(s, "pullFullVector failed", "ref", ref, "err", st.Error())
				return
			}
			if !st.IsComplete() {
				return
			}
			s.onPulledFullVector(st.Content().Join())
		},
	})
}

// onPulledFullVector merges a fetched inline FULL SvsData into local state.
// Segment signatures are validated by client.ConsumeExt during fetch.
func (s *SvSync) onPulledFullVector(content []byte) {
	params, err := parseFullVectorContent(content)
	if err != nil {
		log.Warn(s, "onPulledFullVector parse failed", "err", err)
		return
	}

	s.recvSv <- svSyncRecvSvArgs{
		sv:         params.StateVector,
		vectorType: optional.Some(spec_svs.VectorTypeFull),
		mhash:      params.MemberSetHash,
	}
}

func parseFullVectorContent(content []byte) (*spec_svs.SvsData, error) {
	params, err := spec_svs.ParseSvsData(enc.NewBufferView(content), false)
	if err != nil {
		return nil, err
	}
	if params.StateVector == nil {
		return nil, fmt.Errorf("full vector content has no StateVector")
	}
	if vt, ok := params.VectorType.Get(); ok && vt != spec_svs.VectorTypeFull {
		return nil, fmt.Errorf("full vector VectorType=%d, want FULL", vt)
	}
	if len(params.MemberSetHash) > 0 {
		computed := ComputeMembershipHash(stateVectorToMap(params.StateVector))
		if !bytes.Equal(params.MemberSetHash, computed) {
			return nil, fmt.Errorf("full vector mhash mismatch")
		}
	}
	return params, nil
}

func stateVectorToMap(sv *spec_svs.StateVector) SvMap[uint64] {
	m := NewSvMap[uint64](len(sv.Entries))
	for _, node := range sv.Entries {
		hash := node.Name.TlvStr()
		for _, entry := range node.SeqNoEntries {
			m.Set(hash, entry.BootstrapTime, entry.SeqNo)
		}
	}
	return m
}

// sendRecoveryAnnounce publishes at 32=sv and emits announce-only Sync Data (mhash recovery).
func (s *SvSync) sendRecoveryAnnounce() {
	if !s.running.Load() || s.o.Passive {
		return
	}
	wire := s.encodeSyncData(syncSendRecovery, enc.Name{})
	s.sendSyncInterestWith(wire)
}

// handleMhashMismatch schedules announce or pull recovery on membership mismatch.
func (s *SvSync) handleMhashMismatch(args svSyncRecvSvArgs, recvSv SvMap[uint64]) {
	localMhash := ComputeMembershipHash(s.state)
	if bytes.Equal(localMhash, args.mhash) {
		return
	}

	trustPrefix := pullRefFromSyncDataWire(args.data)
	if len(trustPrefix) == 0 {
		trustPrefix = s.fullVectorPrefix
	}

	localTuples, remoteTuples := membershipTupleCount(s.state), membershipTupleCount(recvSv)
	if localTuples > remoteTuples && membershipContains(s.state, recvSv) {
		go s.sendRecoveryAnnounce()
		return
	}

	// [Spec] Inline FULL is already merged in onReceiveStateVector.
	// Pull only when the sender provided a retrievable SvsDataRef (publish-only sync).
	if len(args.svsDataRef) == 0 {
		return
	}
	go s.pullFullVector(args.svsDataRef, trustPrefix)
}

func membershipContains(outer, inner SvMap[uint64]) bool {
	for hash, vals := range inner {
		for _, v := range vals {
			found := false
			for _, ov := range outer[hash] {
				if ov.Boot == v.Boot {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func membershipTupleCount(m SvMap[uint64]) int {
	n := 0
	for _, vals := range m {
		n += len(vals)
	}
	return n
}

func isTrustedSvsDataRef(ref, senderFullVectorPrefix enc.Name) bool {
	if len(ref) == 0 || len(senderFullVectorPrefix) == 0 {
		return false
	}
	return senderFullVectorPrefix.IsPrefix(ref)
}
