package sync

import (
	"fmt"
	"math"
	rand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

type SvSync struct {
	o SvSyncOpts

	running atomic.Bool
	stop    chan struct{}
	ticker  *time.Ticker

	mutex  sync.Mutex
	state  SvMap[uint64]
	mtime  map[string]time.Time
	prefix enc.Name

	// Suppression state
	suppress bool
	merge    SvMap[uint64]

	// Buffered wires (passive mode)
	passiveWiresSv     SvMap[enc.Wire]
	passiveWillPersist atomic.Bool

	// Channel for incoming state vectors
	recvSv chan svSyncRecvSvArgs

	// cancellation for face hook
	faceCancel func()
}

type SvSyncOpts struct {
	// NDN Object API client
	Client ndn.Client
	// Sync group prefix for the SVS group
	GroupPrefix enc.Name
	// Callback for SVSync updates
	OnUpdate func(SvSyncUpdate)

	// Name of this instance for security
	// This name will be used directly for the Sync Data name;
	// only a version component will be appended.
	// If not provided, the GroupPrefix will be used instead.
	SyncDataName enc.Name

	// Initial state vector from persistence
	InitialState *spec_svs.StateVector
	// Boot time from persistence
	BootTime uint64
	// Periodic timeout for sending Sync Interests (default 30s)
	PeriodicTimeout time.Duration
	// Suppression period for ignoring outdated Sync Interests (default 200ms)
	SuppressionPeriod time.Duration

	// Passive mode does not send sign Sync Interests
	Passive bool
	// IgnoreValidity ignores validity period in the validation chain
	IgnoreValidity optional.Optional[bool]
}

type SvSyncUpdate struct {
	Name enc.Name
	Boot uint64
	High uint64
	Low  uint64
}

type svSyncRecvSvArgs struct {
	sv   *spec_svs.StateVector
	data enc.Wire
}

// NewSvSync creates a new SV Sync instance.
func NewSvSync(opts SvSyncOpts) *SvSync {
	// Check required options
	if opts.Client == nil {
		panic("SvSync: Client is required")
	}
	if len(opts.GroupPrefix) == 0 {
		panic("SvSync: GroupPrefix is required")
	}
	if opts.OnUpdate == nil {
		panic("SvSync: OnUpdate is required")
	}

	// Use initial state if provided
	initialState := NewSvMap[uint64](0)
	if opts.InitialState != nil {
		for _, node := range opts.InitialState.Entries {
			hash := node.Name.TlvStr()
			for _, entry := range node.SeqNoEntries {
				initialState.Set(hash, entry.BootstrapTime, entry.SeqNo)
			}
		}
	}

	// Set default options
	if opts.BootTime == 0 {
		opts.BootTime = uint64(time.Now().Unix())
	}
	if opts.PeriodicTimeout == 0 {
		opts.PeriodicTimeout = 30 * time.Second
	}
	if opts.SuppressionPeriod == 0 {
		opts.SuppressionPeriod = 200 * time.Millisecond
	}
	if len(opts.SyncDataName) == 0 {
		opts.SyncDataName = opts.GroupPrefix
	}

	return &SvSync{
		o: opts,

		running: atomic.Bool{},
		stop:    make(chan struct{}),
		ticker:  time.NewTicker(opts.PeriodicTimeout),

		mutex:  sync.Mutex{},
		state:  initialState,
		mtime:  make(map[string]time.Time),
		prefix: opts.GroupPrefix.Append(enc.NewVersionComponent(3)),

		suppress: false,
		merge:    NewSvMap[uint64](0),

		passiveWiresSv:     NewSvMap[enc.Wire](0),
		passiveWillPersist: atomic.Bool{},

		recvSv: make(chan svSyncRecvSvArgs, 128),

		faceCancel: func() {},
	}
}

// Instance log identifier
func (s *SvSync) String() string {
	return fmt.Sprintf("svs (%s)", s.o.GroupPrefix)
}

// Start the SV Sync instance.
func (s *SvSync) Start() (err error) {
	err = s.o.Client.Engine().AttachHandler(s.prefix,
		func(args ndn.InterestHandlerArgs) {
			s.onSyncInterest(args.Interest)
		})
	if err != nil {
		return err
	}

	go s.main()

	return nil
}

// (AI GENERATED DESCRIPTION): Runs the SvSync event loop: it performs the initial sync (or passive load), registers periodic timer ticks and face‑up callbacks, processes received state vectors, and exits cleanly when signalled to stop.
func (s *SvSync) main() {
	// Cleanup on exit
	defer s.o.Client.Engine().DetachHandler(s.prefix)

	// Set running state
	s.running.Store(true)
	defer s.running.Store(false)

	// Notify everyone when we are back online
	s.faceCancel = s.o.Client.Engine().Face().OnUp(func() {
		time.AfterFunc(100*time.Millisecond, s.sendSyncInterest)
	})
	defer s.faceCancel()

	if s.o.Passive {
		// [Passive] Load the buffered wires from persistence
		// This will send the initial Sync Interest
		go s.loadPassiveWires()
	} else {
		// Send the initial Sync Interest
		go s.sendSyncInterest()
	}

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

// Stop the SV Sync instance.
func (s *SvSync) Stop() error {
	s.ticker.Stop()
	s.persistPassiveWires()
	s.stop <- struct{}{}
	return nil
}

// GetSeqNo returns the sequence number for a name.
func (s *SvSync) GetSeqNo(name enc.Name) uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.state.Get(name.TlvStr(), s.o.BootTime)
}

// SetSeqNo sets the sequence number for a name.
// The instance must only set sequence numbers for names it owns.
// The sequence number must be greater than the previous value.
func (s *SvSync) SetSeqNo(name enc.Name, seqNo uint64) error {
	if s.o.Passive {
		panic("passive sync violation")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	hash := name.TlvStr()

	entry := s.state.Get(hash, s.o.BootTime)
	if seqNo <= entry {
		return fmt.Errorf("SvSync: seqNo must be greater than previous")
	}

	// [Spec] When the node generates a new publication,
	// immediately emit a Sync Interest
	s.state.Set(hash, s.o.BootTime, seqNo)
	go s.sendSyncInterest()

	return nil
}

// IncrSeqNo increments the sequence number for a name.
// The instance must only increment sequence numbers for names it owns.
func (s *SvSync) IncrSeqNo(name enc.Name) uint64 {
	if s.o.Passive {
		panic("passive sync violation")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	hash := name.TlvStr()
	entry := s.state.Get(hash, s.o.BootTime)
	entry++
	s.state.Set(hash, s.o.BootTime, entry)

	// [Spec] When the node generates a new publication,
	// immediately emit a Sync Interest
	go s.sendSyncInterest()

	return entry
}

// (AI GENERATED DESCRIPTION): Returns the boot time value stored in the SvSync instance.
func (s *SvSync) GetBootTime() uint64 {
	return s.o.BootTime
}

// (AI GENERATED DESCRIPTION): Returns a thread‑safe slice of all names currently stored in the SvSync state.
func (s *SvSync) GetNames() []enc.Name {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	names := make([]enc.Name, 0, len(s.state))
	for name := range s.state.Iter() {
		names = append(names, name)
	}

	return names
}

// (AI GENERATED DESCRIPTION): Processes an incoming state vector, updating the local state vector, notifying the application of any changes, and handling suppression and passive‑sync logic while ensuring updates are delivered in order.
func (s *SvSync) onReceiveStateVector(args svSyncRecvSvArgs) {
	// Deliver the updates after this call is done
	// This ensures the mutex is not held during the callback
	// This function, in turn, runs on our main goroutine, so
	// that ensures the updates are delivered in order.
	var updates []SvSyncUpdate
	defer func() {
		for _, update := range updates {
			s.o.OnUpdate(update)
		}
	}()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	isOutdated := false
	canDrop := true
	recvSv := NewSvMap[uint64](len(args.sv.Entries))
	now := time.Now()

	for _, node := range args.sv.Entries {
		hash := node.Name.TlvStr()

		// Walk through the state vector entries in reverse order.
		// The ordering is important so we deliver the newest boot time first.
		for seqi := range node.SeqNoEntries {
			entry := node.SeqNoEntries[len(node.SeqNoEntries)-1-seqi]
			recvSv.Set(hash, entry.BootstrapTime, entry.SeqNo)

			// [SPEC] If any received BootstrapTime is more than 86400s in the
			// future compared to current time, the entire state vector SHOULD be ignored.
			if entry.BootstrapTime > uint64(now.Unix())+86400 {
				log.Warn(s, "Dropping state vector with far future BootstrapTime: %d", entry.BootstrapTime)
				return
			}

			// Get existing state vector entry
			known := s.state.Get(hash, entry.BootstrapTime)
			if entry.SeqNo > known {
				// [Spec] If the incoming state vector is newer,
				// update the local state vector.
				s.state.Set(hash, entry.BootstrapTime, entry.SeqNo)

				// [Spec] Store the current timestamp as the last update
				// time for each updated node.
				s.mtime[hash] = now

				// Notify the application of the update
				updates = append(updates, SvSyncUpdate{
					Name: node.Name,
					Boot: entry.BootstrapTime,
					High: entry.SeqNo,
					Low:  known + 1,
				})
			} else if entry.SeqNo < known {
				isOutdated = true

				// [Spec] If every node with an outdated sequence number
				// in the incoming state vector was updated in the last
				// SuppressionPeriod, drop the Sync Interest.
				if now.After(s.mtime[hash].Add(s.o.SuppressionPeriod)) {
					canDrop = false
				}
			}

			// [Spec] Suppression state
			if s.suppress {
				// [Spec] For every incoming Sync Interest, aggregate
				// the state vector into a MergedStateVector.
				known := s.merge.Get(hash, entry.BootstrapTime)
				if entry.SeqNo > known {
					s.merge.Set(hash, entry.BootstrapTime, entry.SeqNo)
				}
			}

			// [Passive] Buffer the incoming wire
			if s.o.Passive && entry.SeqNo >= known {
				s.passiveWiresSv.Set(hash, entry.BootstrapTime, args.data)
			}
		}
	}

	// The above checks each node in the incoming state vector, but
	// does not check if a node is missing from the incoming state vector.
	if !isOutdated && s.state.IsNewerThan(recvSv, func(_, _ uint64) bool { return false }) {
		isOutdated = true
		canDrop = false
	}

	// [Passive] Persist the buffered wires with throttling
	if s.o.Passive && !s.passiveWillPersist.Swap(true) {
		time.AfterFunc(5*time.Second, s.persistPassiveWires)
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
	s.merge.Clear()

	// [Spec] When entering Suppression State, reset
	// the Sync Interest timer to SuppressionTimeout
	s.ticker.Reset(s.getSuppressionTimeout())
}

// (AI GENERATED DESCRIPTION): Handles a timer expiry by checking suppression state, potentially transitioning to steady state, and asynchronously sending a Sync Interest with the current local state vector.
func (s *SvSync) timerExpired() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// [Spec] Suppression State
	if s.suppress {
		// [Spec] If MergedStateVector is up-to-date; no inconsistency.
		if !s.state.IsNewerThan(s.merge, func(a, b uint64) bool { return a > b }) {
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

// (AI GENERATED DESCRIPTION): Sends a sync Interest: if passive mode is enabled, it publishes all buffered state updates without duplicates; otherwise, it encodes the current state vector into a wire and transmits it, provided the sync service is running.
func (s *SvSync) sendSyncInterest() {
	if !s.running.Load() {
		return
	}

	// [Passive] Send all buffered wires without duplicates
	if s.o.Passive {
		for _, wire := range s.passiveWires() {
			s.sendSyncInterestWith(wire)
		}
		return
	}

	// Encode and sign the current state vector
	wire := s.encodeSyncData()
	s.sendSyncInterestWith(wire)
}

// (AI GENERATED DESCRIPTION): Sends a sync Interest carrying the supplied data wire payload with a 1‑second lifetime, using the object’s prefix, and logs any construction or transmission errors.
func (s *SvSync) sendSyncInterestWith(dataWire enc.Wire) {
	if dataWire == nil {
		return
	}

	intCfg := &ndn.InterestConfig{
		Lifetime: optional.Some(1 * time.Second),
		Nonce:    utils.ConvertNonce(s.o.Client.Engine().Timer().Nonce()),
	}
	interest, err := s.o.Client.Engine().Spec().MakeInterest(s.prefix, intCfg, dataWire, nil)
	if err != nil {
		log.Error(s, "sendSyncInterest failed make interest", "err", err)
		return
	}

	// [Spec] Sync Ack Policy - Do not acknowledge Sync Interests
	err = s.o.Client.Engine().Express(interest, nil)
	if err != nil {
		log.Error(s, "sendSyncInterest failed express", "err", err)
	}
}

// (AI GENERATED DESCRIPTION): Builds a signed Data packet containing the current state vector for SVS v3 synchronization.
func (s *SvSync) encodeSyncData() enc.Wire {
	// Critical section
	sv := func() *spec_svs.StateVector {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		// [Spec*] Sending always triggers Steady State
		s.enterSteadyState()

		return s.state.Encode(func(s uint64) uint64 { return s })
	}()
	svWire := (&spec_svs.SvsData{StateVector: sv}).Encode()

	// SVS v3 Sync Data
	name := s.o.SyncDataName.WithVersion(enc.VersionUnixMicro)

	// Sign Sync Data
	signer := s.o.Client.SuggestSigner(name)
	if signer == nil {
		log.Error(s, "SvSync failed to find valid signer", "name", name)
		return nil
	}

	dataCfg := &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeBlob),
	}
	data, err := s.o.Client.Engine().Spec().MakeData(name, dataCfg, svWire, signer)
	if err != nil {
		log.Error(s, "sendSyncInterest failed make data", "err", err)
		return nil
	}
	return data.Wire
}

// (AI GENERATED DESCRIPTION): Handles a received sync Interest by checking the running state, extracting its AppParam, and passing that payload to the sync‑data processing routine.
func (s *SvSync) onSyncInterest(interest ndn.Interest) {
	if !s.running.Load() {
		return
	}

	// Check if app param is present
	if interest.AppParam() == nil {
		log.Debug(s, "onSyncInterest no AppParam, ignoring")
		return
	}

	// Decode Sync Data
	s.onSyncData(interest.AppParam())
}

// (AI GENERATED DESCRIPTION): Processes a received SyncData packet by parsing it, validating the signature, extracting the state vector, and forwarding the vector and original data to the receiver channel.
func (s *SvSync) onSyncData(dataWire enc.Wire) {
	data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(dataWire))
	if err != nil {
		log.Warn(s, "onSyncInterest failed to parse SyncData", "err", err)
		return
	}

	// Validate signature
	s.o.Client.ValidateExt(ndn.ValidateExtArgs{
		Data:           data,
		SigCovered:     sigCov,
		IgnoreValidity: s.o.IgnoreValidity,
		Callback: func(valid bool, err error) {
			if !valid || err != nil {
				log.Warn(s, "SvSync failed to validate signature", "name", data.Name(), "valid", valid, "err", err)
				return
			}

			// Decode state vector
			svWire := data.Content().Join()
			params, err := spec_svs.ParseSvsData(enc.NewBufferView(svWire), false)
			if err != nil || params.StateVector == nil {
				log.Warn(s, "onSyncInterest failed to parse StateVec", "err", err)
				return
			}

			s.recvSv <- svSyncRecvSvArgs{
				sv:   params.StateVector,
				data: dataWire,
			}
		},
	})
}

// Call with mutex locked
func (s *SvSync) enterSteadyState() {
	s.suppress = false
	// [Spec] Steady state: Reset Sync Interest timer to PeriodicTimeout
	s.ticker.Reset(s.getPeriodicTimeout())
}

// (AI GENERATED DESCRIPTION): Returns a duration uniformly randomized within ±10% of the configured periodic timeout.
func (s *SvSync) getPeriodicTimeout() time.Duration {
	// [Spec] ±10% uniform jitter
	jitter := s.o.PeriodicTimeout / 10
	min := s.o.PeriodicTimeout - jitter
	max := s.o.PeriodicTimeout + jitter
	return time.Duration(rand.Int64N(int64(max-min))) + min
}

// (AI GENERATED DESCRIPTION): Calculates a random suppression timeout duration using an exponential‑decay function based on the configured SuppressionPeriod.
func (s *SvSync) getSuppressionTimeout() time.Duration {
	// [Spec] Exponential decay function
	// [Spec] c = SuppressionPeriod  // constant factor
	// [Spec] v = random(0, c)       // uniform random value
	// [Spec] f = 10.0               // decay factor
	c := float64(s.o.SuppressionPeriod)
	v := float64(rand.Int64N(int64(s.o.SuppressionPeriod)))
	f := float64(10.0)

	// [Spec] SuppressionTimeout = c * (1 - e^((v - c) / (c / f)))
	timeout := time.Duration(c * (1 - math.Pow(math.E, ((v-c)/(c/f)))))

	return timeout
}

// passiveWires returns the list of buffered wires in passive mode.
func (s *SvSync) passiveWires() []enc.Wire {
	outgoing := make([]enc.Wire, 0, 4)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Do not use Iter() because no point decoding the name
	for _, mval := range s.passiveWiresSv {
		for _, val := range mval {
			// A map might actually be slower since the # is small
			found := false
			for _, wire := range outgoing {
				if utils.HeaderEqual(wire, val.Value) {
					found = true
					break
				}
			}
			if !found {
				outgoing = append(outgoing, val.Value)
			}
		}
	}

	return outgoing
}

// persistPassiveWires persists the buffered wires in passive mode.
func (s *SvSync) persistPassiveWires() {
	if !s.o.Passive || !s.running.Load() {
		return
	}

	defer s.passiveWillPersist.Store(false)

	wires := s.passiveWires()
	if len(wires) == 0 {
		log.Info(s, "No passive state to persist")
		return
	}

	pstate := spec_svs.PassiveState{
		Data: make([][]byte, len(wires)),
	}
	for i, wire := range wires {
		pstate.Data[i] = wire.Join()
	}

	name := s.prefix.Append(enc.NewKeywordComponent("passive-state"))
	wire := pstate.Encode().Join()
	if err := s.o.Client.Store().Put(name, wire); err != nil {
		log.Error(s, "Failed to persist wires", "err", err)
	}
}

// loadPassiveWires loads the buffered wires in passive mode.
func (s *SvSync) loadPassiveWires() {
	if !s.o.Passive || !s.running.Load() {
		return
	}

	name := s.prefix.Append(enc.NewKeywordComponent("passive-state"))
	wire, _ := s.o.Client.Store().Get(name, false)
	if wire == nil {
		log.Info(s, "No existing passive state found", "name", name)
		return
	}

	pstate, err := spec_svs.ParsePassiveState(enc.NewBufferView(wire), false)
	if err != nil {
		log.Error(s, "Failed to parse passive state", "err", err)
		return
	}

	log.Info(s, "Loading passive state", "name", name)
	for _, data := range pstate.Data {
		s.onSyncData(enc.Wire{data})
	}

	// This is hacky but pragmatic - wait for the state to be processed
	time.AfterFunc(500*time.Millisecond, s.sendSyncInterest)
}
