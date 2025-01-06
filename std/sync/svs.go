package sync

import (
	"errors"
	"math"
	rand "math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	stlv "github.com/named-data/ndnd/std/ndn/svs_2024"
	"github.com/named-data/ndnd/std/utils"
)

type SvSync struct {
	engine      ndn.Engine
	groupPrefix enc.Name
	onUpdate    func(SvSyncUpdate)

	running atomic.Bool
	stop    chan struct{}
	ticker  *time.Ticker

	periodicTimeout   time.Duration
	suppressionPeriod time.Duration

	mutex sync.Mutex
	state map[uint64]uint64
	names map[uint64]enc.Name
	mtime map[uint64]time.Time

	suppress bool
	merge    map[uint64]uint64

	recvSv chan *stlv.StateVector
}

type SvSyncUpdate struct {
	NodeId enc.Name
	High   uint64
	Low    uint64
}

func NewSvSync(
	engine ndn.Engine,
	groupPrefix enc.Name,
	onUpdate func(SvSyncUpdate),
) *SvSync {
	return &SvSync{
		engine:      engine,
		groupPrefix: groupPrefix.Clone(),
		onUpdate:    onUpdate,

		running: atomic.Bool{},
		stop:    make(chan struct{}),
		ticker:  time.NewTicker(1 * time.Second),

		periodicTimeout:   30 * time.Second,
		suppressionPeriod: 200 * time.Millisecond,

		mutex: sync.Mutex{},
		state: make(map[uint64]uint64),
		names: make(map[uint64]enc.Name),
		mtime: make(map[uint64]time.Time),

		suppress: false,
		merge:    make(map[uint64]uint64),

		recvSv: make(chan *stlv.StateVector, 128),
	}
}

func (s *SvSync) Start() (err error) {
	err = s.engine.AttachHandler(s.groupPrefix, func(args ndn.InterestHandlerArgs) {
		go s.onSyncInterest(args.Interest)
	})
	if err != nil {
		return err
	}

	go s.main()
	go s.sendSyncInterest()

	return nil
}

func (s *SvSync) main() {
	defer s.engine.DetachHandler(s.groupPrefix)

	s.running.Store(true)
	defer s.running.Store(false)

	for {
		select {
		case <-s.ticker.C:
			s.timerExpired()
		case sv := <-s.recvSv:
			s.onReceiveStateVector(sv)
		case <-s.stop:
			return
		}
	}
}

func (s *SvSync) Stop() {
	s.ticker.Stop()
	s.stop <- struct{}{}
	close(s.stop)
}

func (s *SvSync) SetSeqNo(nodeId enc.Name, seqNo uint64) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	hash := s.hashName(nodeId)
	prev := s.state[hash]

	if seqNo <= prev {
		return errors.New("SvSync: seqNo must be greater than previous")
	}

	// [Spec] When the node generates a new publication,
	// immediately emit a Sync Interest
	s.state[hash] = seqNo
	go s.sendSyncInterest()

	return nil
}

func (s *SvSync) GetSeqNo(nodeId enc.Name) uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	hash := s.hashName(nodeId)
	return s.state[hash]
}

func (s *SvSync) IncrSeqNo(nodeId enc.Name) uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	hash := s.hashName(nodeId)
	val := s.state[hash] + 1
	s.state[hash] = val

	// [Spec] When the node generates a new publication,
	// immediately emit a Sync Interest
	go s.sendSyncInterest()

	return val
}

func (s *SvSync) hashName(nodeId enc.Name) uint64 {
	hash := nodeId.Hash()
	if _, ok := s.names[hash]; !ok {
		s.names[hash] = nodeId.Clone()
	}
	return hash
}

func (s *SvSync) onReceiveStateVector(sv *stlv.StateVector) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	isOutdated := false
	canDrop := true
	recvSet := make(map[uint64]bool)

	for _, entry := range sv.Entries {
		hash := s.hashName(entry.NodeId)
		recvSet[hash] = true

		prev := s.state[hash]
		if entry.SeqNo > prev {
			// [Spec] If the incoming state vector is newer,
			// update the local state vector.
			s.state[hash] = entry.SeqNo

			// [Spec] Store the current timestamp as the last update
			// time for each updated node.
			s.mtime[hash] = time.Now()

			// Notify the application of the update
			s.onUpdate(SvSyncUpdate{
				NodeId: entry.NodeId,
				High:   entry.SeqNo,
				Low:    prev + 1,
			})
		} else if entry.SeqNo < prev {
			isOutdated = true

			// [Spec] If every node with an outdated sequence number
			// in the incoming state vector was updated in the last
			// SuppressionPeriod, drop the Sync Interest.
			if time.Now().After(s.mtime[hash].Add(s.suppressionPeriod)) {
				canDrop = false
			}
		}

		// [Spec] Suppression state
		if s.suppress {
			// [Spec] For every incoming Sync Interest, aggregate
			// the state vector into a MergedStateVector.
			if entry.SeqNo > s.merge[hash] {
				s.merge[hash] = entry.SeqNo
			}
		}
	}

	// The above checks each node in the incoming state vector, but
	// does not check if a node is missing from the incoming state vector.
	if !isOutdated {
		for nodeId := range s.state {
			if _, ok := recvSet[nodeId]; !ok {
				isOutdated = true
				canDrop = false
				break
			}
		}
	}

	if !isOutdated {
		// [Spec] Suppression state: Move to Steady State.
		// [Spec] Steady state: Reset Sync Interest timer.
		s.enterSteadyState()
		return
	} else if canDrop || s.suppress {
		// See above for explanation
		return
	}

	// [Spec] Incoming Sync Interest is outdated.
	// [Spec] Move to Suppression State.
	s.suppress = true
	s.merge = make(map[uint64]uint64)

	// [Spec] When entering Suppression State, reset
	// the Sync Interest timer to SuppressionTimeout
	s.ticker.Reset(s.getSuppressionTimeout())
}

func (s *SvSync) timerExpired() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// [Spec] Suppression State
	if s.suppress {
		// [Spec] If MergedStateVector is up-to-date; no inconsistency.
		send := false
		for nodeId, seqNo := range s.state {
			if seqNo > s.merge[nodeId] {
				send = true
				break
			}
		}
		if !send {
			s.enterSteadyState()
			return
		}
		// [Spec] If MergedStateVector is outdated; inconsistent state.
		// Emit up-to-date Sync Interest.
	}

	// [Spec] On expiration of timer emit a Sync Interest
	// with the current local state vector.
	go s.sendSyncInterest()
}

func (s *SvSync) sendSyncInterest() {
	if !s.running.Load() {
		return
	}

	// Critical section
	svWire := func() enc.Wire {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		// [Spec*] Sending always triggers Steady State
		s.enterSteadyState()

		return s.encodeSv()
	}()

	// SVS v2 Sync Interest
	syncName := s.groupPrefix.Append(enc.NewVersionComponent(2))

	// Sync Interest parameters for SVS
	cfg := &ndn.InterestConfig{
		Lifetime: utils.IdPtr(1 * time.Second),
		Nonce:    utils.ConvertNonce(s.engine.Timer().Nonce()),
	}

	// TODO: sign the sync interest

	interest, err := s.engine.Spec().MakeInterest(syncName, cfg, svWire, nil)
	if err != nil {
		log.Errorf("SvSync: sendSyncInterest failed make: %+v", err)
		return
	}

	// [Spec] Sync Ack Policy - Do not acknowledge Sync Interests
	err = s.engine.Express(interest, nil)
	if err != nil {
		log.Errorf("SvSync: sendSyncInterest failed express: %+v", err)
	}
}

func (s *SvSync) onSyncInterest(interest ndn.Interest) {
	if !s.running.Load() {
		return
	}

	// Check if app param is present
	if interest.AppParam() == nil {
		log.Debug("SvSync: onSyncInterest no AppParam, ignoring")
		return
	}

	// TODO: verify signature on Sync Interest

	// Decode state vector
	raw := enc.Wire{interest.AppParam().Join()}
	params, err := stlv.ParseStateVectorAppParam(enc.NewWireReader(raw), false)
	if err != nil || params.StateVector == nil {
		log.Warnf("SvSync: onSyncInterest failed to parse StateVec: %+v", err)
		return
	}

	s.recvSv <- params.StateVector
}

// Call with mutex locked
func (s *SvSync) encodeSv() enc.Wire {
	entries := make([]*stlv.StateVectorEntry, 0, len(s.state))
	for nodeId, seqNo := range s.state {
		entries = append(entries, &stlv.StateVectorEntry{
			NodeId: s.names[nodeId],
			SeqNo:  seqNo,
		})
	}

	// Sort entries by in the NDN canonical order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].NodeId.Compare(entries[j].NodeId) < 0
	})

	params := stlv.StateVectorAppParam{
		StateVector: &stlv.StateVector{Entries: entries},
	}

	return params.Encode()
}

// Call with mutex locked
func (s *SvSync) enterSteadyState() {
	s.suppress = false
	// [Spec] Steady state: Reset Sync Interest timer to PeriodicTimeout
	s.ticker.Reset(s.getPeriodicTimeout())
}

func (s *SvSync) getPeriodicTimeout() time.Duration {
	// [Spec] ±10% uniform jitter
	jitter := s.periodicTimeout / 10
	min := s.periodicTimeout - jitter
	max := s.periodicTimeout + jitter
	return time.Duration(rand.Int64N(int64(max-min))) + min
}

func (s *SvSync) getSuppressionTimeout() time.Duration {
	// [Spec] Exponential decay function
	// [Spec] c = SuppressionPeriod  // constant factor
	// [Spec] v = random(0, c)       // uniform random value
	// [Spec] f = 10.0               // decay factor
	c := float64(s.suppressionPeriod)
	v := float64(rand.Int64N(int64(s.suppressionPeriod)))
	f := float64(10.0)

	// [Spec] SuppressionTimeout = c * (1 - e^((v - c) / (c / f)))
	timeout := time.Duration(c * (1 - math.Pow(math.E, ((v-c)/(c/f)))))

	return timeout
}
