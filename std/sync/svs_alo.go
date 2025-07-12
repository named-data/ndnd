package sync

import (
	gosync "sync"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
)

// SvsALO is a Sync Transport with At Least One delivery semantics.
type SvsALO struct {
	// opts is the configuration options.
	opts SvsAloOpts
	// svs is the underlying Sync Transport.
	svs *SvSync
	// client is the object client.
	client ndn.Client
	// group is the group prefix.
	group enc.Name

	// mutex protects the instance.
	mutex gosync.Mutex

	// state is the current state.
	state SvMap[svsDataState]
	// nodePs is the Pub/Sub coordinator for publisher prefixes
	nodePs SimplePs[SvsPub]

	// outpipe is the channel for delivering data.
	outpipe chan SvsPub
	// errpipe is the channel for delivering errors.
	errpipe chan error
	// publpipe is the channel for delivering new publishers.
	publpipe chan enc.Name
	// stop is the stop signal.
	stop chan struct{}

	// error callback
	onError func(error)
	// publisher callback
	onPublisher func(enc.Name)
}

type SvsAloOpts struct {
	// Name is the name of this instance producer.
	Name enc.Name
	// Svs is the options for the underlying SVS instance.
	Svs SvSyncOpts
	// Snapshot is the snapshot strategy.
	Snapshot Snapshot
	// InitialState is the initial state of the instance.
	InitialState enc.Wire

	// MaxPipelineSize is the number of objects to fetch
	// concurrently for a single publisher (default 10)
	MaxPipelineSize uint64

	// MulticastPrefix is a prefix to prepend to Sync Interests
	MulticastPrefix enc.Name
}

// NewSvsALO creates a new SvsALO instance.
func NewSvsALO(opts SvsAloOpts) (*SvsALO, error) {
	if len(opts.Name) == 0 {
		panic("Name is required")
	}

	s := &SvsALO{
		opts:   opts,
		svs:    nil,
		client: opts.Svs.Client,
		group:  opts.Svs.GroupPrefix,

		mutex: gosync.Mutex{},

		state:  NewSvMap[svsDataState](0),
		nodePs: NewSimplePs[SvsPub](),

		outpipe:  make(chan SvsPub, 256),
		errpipe:  make(chan error, 16),
		publpipe: make(chan enc.Name, 16),
		stop:     make(chan struct{}),

		onError:     func(err error) { log.Warn(nil, err.Error()) },
		onPublisher: nil,
	}

	// Default options
	if s.opts.MaxPipelineSize == 0 {
		s.opts.MaxPipelineSize = 10
	}

	// Read initial state if provided.
	s.opts.Svs.OnUpdate = s.onSvsUpdate
	if s.opts.InitialState != nil {
		if err := s.parseInstanceState(s.opts.InitialState); err != nil {
			return nil, err
		}
	}

	// Configure SVS options
	if s.opts.Svs.BootTime == 0 {
		// This is actually done by the SVS instance itself, but we need
		// it to tell the SyncDataName to SVS ...
		s.opts.Svs.BootTime = uint64(time.Now().Unix())
	}

	// Svs.GroupPrefix is actually the Sync prefix
	s.opts.Svs.GroupPrefix = s.GroupPrefix().Append(enc.NewKeywordComponent("svs"))
	if s.opts.MulticastPrefix != nil {
		s.opts.Svs.GroupPrefix = s.opts.MulticastPrefix.Append(s.opts.Svs.GroupPrefix...)
	}

	// SyncDataName is the name of the SVS data (for security)
	s.opts.Svs.SyncDataName = s.DataPrefix().Append(enc.NewKeywordComponent("svs"))

	// Initialize the underlying SVS instance
	s.svs = NewSvSync(s.opts.Svs)

	// Initialize the state vector with our own state.
	// If initial state is provided, this should be equal.
	seqNo := s.svs.GetSeqNo(s.opts.Name)
	s.state.Set(s.opts.Name.TlvStr(), s.BootTime(), svsDataState{
		Known:   seqNo,
		Latest:  seqNo,
		Pending: seqNo,
	})

	// Configure the snapshot strategy.
	if s.opts.Snapshot == nil {
		s.opts.Snapshot = &SnapshotNull{}
	} else {
		s.opts.Snapshot.initialize(snapPsState{
			nodePrefix:  s.opts.Name,
			groupPrefix: s.GroupPrefix(),
			bootTime:    s.BootTime(),
			onSnap:      s.snapRecvCallback,
		}, s.state)
	}

	// Overeide IgnoreValidity from SVS (incorect but practical)
	if latest, ok := s.opts.Snapshot.(*SnapshotNodeLatest); ok {
		latest.IgnoreValidity = s.opts.Svs.IgnoreValidity
	}
	if history, ok := s.opts.Snapshot.(*SnapshotNodeHistory); ok {
		history.IgnoreValidity = s.opts.Svs.IgnoreValidity
	}

	return s, nil
}

// String is the log identifier.
func (s *SvsALO) String() string {
	return "svs-alo"
}

// GroupPrefix is the group prefix for this instance.
func (s *SvsALO) GroupPrefix() enc.Name {
	return s.group
}

// SyncPrefix is the sync route prefix for this instance.
func (s *SvsALO) SyncPrefix() enc.Name {
	return s.opts.Svs.GroupPrefix
}

// DataPrefix is the data route prefix for this instance.
func (s *SvsALO) DataPrefix() enc.Name {
	return s.GroupPrefix().
		Append(s.opts.Name...).
		Append(enc.NewTimestampComponent(s.BootTime()))
}

// BootTime returns the boot time of the instance.
func (s *SvsALO) BootTime() uint64 {
	return s.opts.Svs.BootTime
}

// SeqNo returns the current sequence number of the instance.
func (s *SvsALO) SeqNo() uint64 {
	return s.svs.GetSeqNo(s.opts.Name)
}

// SVS returns the underlying SVS instance.
func (s *SvsALO) SVS() *SvSync {
	return s.svs
}

// Start starts the SvsALO instance.
func (s *SvsALO) Start() error {
	if err := s.svs.Start(); err != nil {
		return err
	}

	// SVS is stopped when the main loop quits.
	go s.run()
	return nil
}

// Stop stops the SvsALO instance.
func (s *SvsALO) Stop() error {
	s.stop <- struct{}{}
	s.svs.Stop()
	return nil
}

// SetOnError sets the error callback.
// You can likely cast the received error as SyncError.
//
// SyncError includes the name of the affected publisher and the error.
// Applications can use this callback to selectively unsubscribe from
// publishers that are not responding.
func (s *SvsALO) SetOnError(callback func(error)) {
	s.onError = callback
}

// SetOnPublisher sets the publisher callback.
//
// This will be called when an update from a new publisher is received.
// This includes both updates for publishers that are already subscribed
// and other non-subscribed publishers. Applications can use this callback
// to test the liveness of publishers and selectively subscribe to them.
func (s *SvsALO) SetOnPublisher(callback func(enc.Name)) {
	s.onPublisher = callback
}

// Publish sends a message to the group
func (s *SvsALO) Publish(content enc.Wire) (name enc.Name, state enc.Wire, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.produceObject(content)
}

// SubscribePublisher subscribes to all publishers matchin a name prefix.
// Only one subscriber per prefix is allowed.
// If the prefix is already subscribed, the callback is replaced.
func (s *SvsALO) SubscribePublisher(prefix enc.Name, callback func(SvsPub)) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.nodePs.Subscribe(prefix, callback)
	if err != nil {
		return err
	}

	// Trigger a fetch for all known producers matching this prefix.
	for node := range s.state.Iter() {
		if prefix.IsPrefix(node) {
			s.consumeCheck(node)
		}
	}

	return nil
}

// UnsubscribePublisher unsubscribes removes callbacks added with subscribe.
// The callback may still receive messages for some time after this call.
// The application must handle these messages correctly.
func (s *SvsALO) UnsubscribePublisher(prefix enc.Name) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.nodePs.Unsubscribe(prefix)
}

// run is the main loop for the SvsALO instance.
// Only this thread has interaction with the application.
func (s *SvsALO) run() {
	for {
		select {
		case <-s.stop:
			return
		case pub := <-s.outpipe:
			for _, subscription := range pub.subcribers {
				subscription(pub)
			}
		case err := <-s.errpipe:
			s.onError(err)
		case publ := <-s.publpipe:
			s.onPublisher(publ)
		}
	}
}

// onSvsUpdate is the handler for new sequence numbers.
func (s *SvsALO) onSvsUpdate(update SvSyncUpdate) {
	defer func() {
		if s.onPublisher != nil {
			s.publpipe <- update.Name
		}
	}()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Update the latest known state.
	hash := update.Name.TlvStr()
	entry := s.state.Get(hash, update.Boot)
	entry.Latest = update.High
	s.state.Set(hash, update.Boot, entry)

	// Check if we want to queue new fetch for this update.
	s.consumeCheck(update.Name)
}
