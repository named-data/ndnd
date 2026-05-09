package dv

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	"github.com/named-data/ndnd/dv/table"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
	ndn_sync "github.com/named-data/ndnd/std/sync"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

type PrefixModule struct {
	mu                 sync.Mutex
	pfx                *table.PrefixEgreState
	pfxSvs             *ndn_sync.SvsALO
	nfdc               *nfdc.NfdMgmtThread
	client             ndn.Client
	insertionTrust     *sec.TrustConfig
	replicatePes       bool
	pfxGroup           enc.Name
	insertPrefix       enc.Name
	pfxSeen            map[uint64]enc.Name
	pfxSubs            map[uint64]enc.Name
	petPrefixes        map[uint64]map[string]enc.Name
	seenPrefixVersions map[string]uint64
	prefixPruneStop    chan struct{}
	faceEventsStop     chan struct{}
	faceEventsDone     chan struct{}
	activeFacesMu      sync.RWMutex
	activeFaces        map[uint64]struct{}
	seenFaces          map[uint64]struct{}
	routerName         enc.Name
}

type petEgressOp struct {
	add       bool
	name      enc.Name
	egress    enc.Name
	multicast bool
}

type petNextHopOp struct {
	verb string
	name enc.Name
	face uint64
	cost uint64
}

// const PrefixSnapThreshold = 50

func NewPrefixModule(
	config *config.Config,
	objectClient ndn.Client,
	insertionTrust *sec.TrustConfig,
	nfdcThread *nfdc.NfdMgmtThread,
) *PrefixModule {
	var ptable *table.PrefixEgreState

	// Subscription List
	pfxSubs := make(map[uint64]enc.Name)
	pfxSeen := make(map[uint64]enc.Name)
	petPrefixes := make(map[uint64]map[string]enc.Name)
	seenPrefixVersions := make(map[string]uint64)

	// SVS delivery agent for syncing prefix egress state across all NDN routers.
	pfxSvs, err := ndn_sync.NewSvsALO(ndn_sync.SvsAloOpts{
		Name: config.RouterName(),
		Svs: ndn_sync.SvSyncOpts{
			Client:          objectClient,
			GroupPrefix:     config.PrefixEgreStatePrefix(),
			PeriodicTimeout: config.PrefixSyncInterval(),
		},
		Snapshot: &ndn_sync.SnapshotNodeLatest{
			Client: objectClient,
			SnapMe: func(name enc.Name) (enc.Wire, error) {
				return ptable.Snap(), nil
			},
			Threshold: PrefixSnapThreshold,
		},
	})
	if err != nil {
		panic(err)
	}

	// Local prefix egress state.
	ptable = table.NewPrefixEgreState(config, func(w enc.Wire) {
		if _, _, err := pfxSvs.Publish(w); err != nil {
			log.Error(ptable, "Failed to publish prefix egress state update", "err", err)
		}
	})

	pfxModule := &PrefixModule{
		mu:             sync.Mutex{},
		pfx:            ptable,
		pfxSvs:         pfxSvs,
		nfdc:           nfdcThread,
		client:         objectClient,
		insertionTrust: insertionTrust,
		replicatePes:   config.PrefixEgreStateReplicationEnabled(),
		pfxGroup:       config.PrefixEgreStatePrefix().Clone(),
		insertPrefix: enc.LOCALHOP.
			Append(enc.NewGenericComponent("route")).
			Append(enc.NewGenericComponent("insert")),
		pfxSeen:            pfxSeen,
		pfxSubs:            pfxSubs,
		petPrefixes:        petPrefixes,
		seenPrefixVersions: seenPrefixVersions,
		activeFaces:        make(map[uint64]struct{}),
		seenFaces:          make(map[uint64]struct{}),
		routerName:         config.RouterName(),
	}
	pfxSvs.SetOnPublisher(pfxModule.onPublisher)
	if !pfxModule.replicatePes {
		log.Warn(pfxModule, "Prefix egress state replication to PET is disabled")
	}
	if pfxModule.insertionTrust == nil {
		panic("prefix insertion trust configuration must not be nil")
	}

	return pfxModule
}

func (pfx *PrefixModule) Start() {
	pfx.pfxSvs.Start()
	pfx.startFaceEvents()
	pfx.startPrefixPrune()
	pfx.pfx.Reset()
}

func (pfx *PrefixModule) Stop() {
	pfx.stopPrefixPrune()
	pfx.stopFaceEvents()
	pfx.pfxSvs.Stop()
}

func (pfx *PrefixModule) onPublisher(name enc.Name) {
	if name.Equal(pfx.routerName) {
		return
	}

	hash := name.Hash()
	var shouldInstall bool
	var shouldSubscribe bool

	pfx.mu.Lock()
	if _, ok := pfx.pfxSeen[hash]; !ok {
		pfx.pfxSeen[hash] = name.Clone()
		shouldInstall = true
	}
	if _, ok := pfx.pfxSubs[hash]; !ok {
		pfx.pfxSubs[hash] = name.Clone()
		shouldSubscribe = true
	}
	pfx.mu.Unlock()

	if shouldInstall && pfx.replicatePes {
		if pfx.nfdc != nil {
			route := pfx.pfxGroup.Append(name...)
			pfx.nfdc.Exec(nfdc.NfdMgmtCmd{
				Module: "pet",
				Cmd:    "add-egress",
				Args: &mgmt.ControlArgs{
					Name:   route,
					Egress: &mgmt.EgressRecord{Name: name.Clone()},
				},
				Retries: -1,
			})
		}
	}
	if shouldSubscribe {
		err := pfx.pfxSvs.SubscribePublisher(name, func(sp ndn_sync.SvsPub) {
			pfx.mu.Lock()
			_, petOps := pfx.processUpdate(sp.Content)
			pfx.mu.Unlock()
			pfx.applyPetOps(petOps)
		})
		if err == nil {
			log.Info(pfx.pfx, "Subscribed to prefix updates", "name", name)
			return
		}

		log.Warn(pfx.pfx, "Failed to subscribe to prefix updates", "name", name, "err", err)
		pfx.mu.Lock()
		delete(pfx.pfxSubs, hash)
		pfx.mu.Unlock()
	}
}

// forward APIs from PrefixEgreState
// threadsafe as original caller used a mutex, to maintain existing assumptions

// (AI GENERATED DESCRIPTION): Returns the literal string `"prefix-daemon"` as the string representation of a PrefixModule instance.
func (pfx *PrefixModule) String() string {
	return "prefix-daemon"
}

// (AI GENERATED DESCRIPTION): Retrieves the PrefixEgreStateRouter for a given name, creating a new router with an empty Prefixes map if one does not already exist.
func (pfx *PrefixModule) GetRouter(name enc.Name) *table.PrefixEgreStateRouter {
	pfx.mu.Lock()
	defer pfx.mu.Unlock()

	return pfx.pfx.GetRouter(name)
}

// Reset clears local prefix egress state and publishes a reset update.
func (pfx *PrefixModule) Reset() {
	pfx.mu.Lock()
	petOps := pfx.resetRouterPet(pfx.routerName)
	pfx.pfx.Reset()
	pfx.mu.Unlock()

	pfx.applyPetOps(petOps)
}

// Announce adds or updates a local prefix in prefix egress state.
// Use face=0 and cost=0 for route-only semantics.
func (pfx *PrefixModule) Announce(name enc.Name, face uint64, cost uint64, multicast bool, validity *spec.ValidityPeriod) {
	pfx.announce(name, face, cost, multicast, validity)
}

func (pfx *PrefixModule) announce(name enc.Name, face uint64, cost uint64, multicast bool, validity *spec.ValidityPeriod) {
	pfx.mu.Lock()
	petOps := pfx.addRouterPrefixPet(pfx.routerName, name, multicast)
	pfx.pfx.Announce(name, face, cost, multicast, validity)
	pfx.mu.Unlock()

	pfx.applyPetOps(petOps)
	if face != 0 {
		pfx.applyNextHopOps([]petNextHopOp{{
			verb: "add-nexthop",
			name: name.Clone(),
			face: face,
			cost: cost,
		}})
	}
}

// (AI GENERATED DESCRIPTION): Removes a next‑hop for the specified name and face from the local prefix egress state and republishes the entry if its cost changes.
func (pfx *PrefixModule) Withdraw(name enc.Name, face uint64) {
	pfx.mu.Lock()
	petOps := make([]petEgressOp, 0)
	pfx.pfx.Withdraw(name, face)
	if _, ok := pfx.pfx.GetRouter(pfx.routerName).Prefixes[name.TlvStr()]; !ok {
		petOps = append(petOps, pfx.removeRouterPrefixPet(pfx.routerName, name)...)
	}
	pfx.mu.Unlock()

	pfx.applyPetOps(petOps)
	if face != 0 {
		pfx.applyNextHopOps([]petNextHopOp{{
			verb: "remove-nexthop",
			name: name.Clone(),
			face: face,
		}})
	}
}

func (pfx *PrefixModule) WithdrawRoute(name enc.Name) {
	pfx.mu.Lock()
	petOps := pfx.removeRouterPrefixPet(pfx.routerName, name)
	pfx.pfx.Withdraw(name, 0)
	pfx.mu.Unlock()

	pfx.applyPetOps(petOps)
}

// Applies ops from a list. Returns if dirty.
func (pfx *PrefixModule) Apply(wire enc.Wire) (dirty bool) {
	pfx.mu.Lock()
	dirty, petOps := pfx.processUpdate(wire)
	pfx.mu.Unlock()

	pfx.applyPetOps(petOps)
	return dirty
}

// (AI GENERATED DESCRIPTION): Creates a wire‑encoded TLV PrefixOpList that resets the prefix egress state and lists all current prefixes for the local router.
func (pfx *PrefixModule) Snap() enc.Wire {
	pfx.mu.Lock()
	defer pfx.mu.Unlock()

	return pfx.pfx.Snap()
}

func (pfx *PrefixModule) SnapshotEntries() []table.PrefixSnapshotEntry {
	pfx.mu.Lock()
	defer pfx.mu.Unlock()

	return pfx.pfx.SnapshotEntries()
}

func (pfx *PrefixModule) EntryCount() int {
	pfx.mu.Lock()
	defer pfx.mu.Unlock()

	return pfx.pfx.EntryCount()
}

// information for svs group, need to expose for now to register with mgmt
func (pfx *PrefixModule) SyncPrefix() enc.Name {
	return pfx.pfxSvs.SyncPrefix()
}

func (pfx *PrefixModule) DataPrefix() enc.Name {
	return pfx.pfxSvs.DataPrefix()
}

func (pfx *PrefixModule) InsertionPrefix() enc.Name {
	return pfx.insertPrefix.Clone()
}

func (pfx *PrefixModule) OnInsertion(args ndn.InterestHandlerArgs) {
	pfx.onInsertion(args)
}

func (pfx *PrefixModule) processUpdate(wire enc.Wire) (dirty bool, petOps []petEgressOp) {
	petOps = make([]petEgressOp, 0)

	ops, err := tlv.ParsePrefixOpList(enc.NewWireView(wire), true)
	if err == nil && ops != nil && ops.EgressRouter != nil && len(ops.EgressRouter.Name) > 0 {
		router := ops.EgressRouter.Name.Clone()
		if ops.PrefixOpReset {
			petOps = append(petOps, pfx.resetRouterPet(router)...)
		}
		for _, add := range ops.PrefixOpAdds {
			petOps = append(petOps, pfx.addRouterPrefixPet(router, add.Name, add.Multicast)...)
		}
		for _, remove := range ops.PrefixOpRemoves {
			petOps = append(petOps, pfx.removeRouterPrefixPet(router, remove.Name)...)
		}
	}

	return pfx.pfx.Apply(wire), petOps
}

func (pfx *PrefixModule) resetRouterPet(router enc.Name) []petEgressOp {
	routerHash := router.Hash()
	prefixes, ok := pfx.petPrefixes[routerHash]
	if !ok || len(prefixes) == 0 {
		return nil
	}

	egress := router.Clone()
	ops := make([]petEgressOp, 0, len(prefixes))
	for _, name := range prefixes {
		ops = append(ops, petEgressOp{
			add:    false,
			name:   name.Clone(),
			egress: egress.Clone(),
		})
	}
	delete(pfx.petPrefixes, routerHash)
	return ops
}

func (pfx *PrefixModule) addRouterPrefixPet(router enc.Name, prefix enc.Name, multicast bool) []petEgressOp {
	routerHash := router.Hash()
	prefixes := pfx.petPrefixes[routerHash]
	if prefixes == nil {
		prefixes = make(map[string]enc.Name)
		pfx.petPrefixes[routerHash] = prefixes
	}

	key := prefix.TlvStr()
	if _, exists := prefixes[key]; exists {
		return nil
	}
	prefixes[key] = prefix.Clone()

	egress := router.Clone()
	return []petEgressOp{{
		add:       true,
		name:      prefix.Clone(),
		egress:    egress,
		multicast: multicast,
	}}
}

func (pfx *PrefixModule) removeRouterPrefixPet(router enc.Name, prefix enc.Name) []petEgressOp {
	routerHash := router.Hash()
	prefixes, ok := pfx.petPrefixes[routerHash]
	if !ok {
		return nil
	}

	key := prefix.TlvStr()
	if _, exists := prefixes[key]; !exists {
		return nil
	}
	delete(prefixes, key)
	if len(prefixes) == 0 {
		delete(pfx.petPrefixes, routerHash)
	}

	egress := router.Clone()
	return []petEgressOp{{
		add:    false,
		name:   prefix.Clone(),
		egress: egress,
	}}
}

func (pfx *PrefixModule) applyPetOps(ops []petEgressOp) {
	if !pfx.replicatePes || pfx.nfdc == nil || len(ops) == 0 {
		return
	}

	for _, op := range ops {
		cmd := "remove-egress"
		args := &mgmt.ControlArgs{
			Name:   op.name,
			Egress: &mgmt.EgressRecord{Name: op.egress},
		}
		if op.add {
			cmd = "add-egress"
			if op.multicast {
				args.Multicast = true
			}
		}

		pfx.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module:  "pet",
			Cmd:     cmd,
			Args:    args,
			Retries: -1,
		})
	}
}

func (pfx *PrefixModule) applyNextHopOps(ops []petNextHopOp) {
	if pfx.nfdc == nil || len(ops) == 0 {
		return
	}

	for _, op := range ops {
		cmd := op.verb
		args := &mgmt.ControlArgs{
			Name:   op.name,
			FaceId: optional.Some(op.face),
		}
		switch cmd {
		case "add-nexthop":
			args.Cost = optional.Some(op.cost)
		case "remove-nexthop":
			// no additional parameters
		default:
			log.Warn(pfx, "Unknown PET nexthop command", "cmd", cmd, "name", op.name, "face", op.face)
			continue
		}

		pfx.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module:  "pet",
			Cmd:     cmd,
			Args:    args,
			Retries: -1,
		})
	}
}

func (pfx *PrefixModule) startPrefixPrune() {
	pfx.mu.Lock()
	if pfx.prefixPruneStop != nil {
		pfx.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	pfx.prefixPruneStop = stop
	pfx.mu.Unlock()

	go func(stopCh <-chan struct{}) {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pfx.pruneMissingFaces()
				pfx.pruneExpired()
			case <-stopCh:
				return
			}
		}
	}(stop)
}

func (pfx *PrefixModule) stopPrefixPrune() {
	pfx.mu.Lock()
	stop := pfx.prefixPruneStop
	pfx.prefixPruneStop = nil
	pfx.mu.Unlock()

	if stop != nil {
		close(stop)
	}
}

func (pfx *PrefixModule) pruneExpired() {
	now := time.Now().UTC()

	pfx.mu.Lock()
	expired, _ := pfx.pfx.PruneExpired(now)
	petOps := make([]petEgressOp, 0, len(expired))
	for _, item := range expired {
		petOps = append(petOps, pfx.removeRouterPrefixPet(item.Router, item.Name)...)
	}
	pfx.mu.Unlock()

	pfx.applyPetOps(petOps)
}

func (pfx *PrefixModule) pruneMissingFaces() {
	if pfx.client == nil {
		return
	}

	active, observed := pfx.activeFaceSnapshot()

	type staleRoute struct {
		name enc.Name
		face uint64
	}
	stale := make([]staleRoute, 0)
	seenRoutes := make(map[string]struct{})

	pfx.mu.Lock()
	me := pfx.pfx.GetRouter(pfx.routerName)
	for _, entry := range me.Prefixes {
		for _, nh := range entry.NextHops {
			if nh.Face == 0 {
				continue
			}
			// Without a list bootstrap, we only prune faces we have observed
			// through the event stream.
			if _, ok := observed[nh.Face]; !ok {
				continue
			}
			if _, ok := active[nh.Face]; ok {
				continue
			}

			key := entry.Name.TlvStr() + "#" + strconv.FormatUint(nh.Face, 10)
			if _, exists := seenRoutes[key]; exists {
				continue
			}
			seenRoutes[key] = struct{}{}
			stale = append(stale, staleRoute{
				name: entry.Name.Clone(),
				face: nh.Face,
			})
		}
	}
	pfx.mu.Unlock()

	for _, route := range stale {
		log.Info(pfx, "Pruning prefix route due to missing face", "name", route.name, "faceid", route.face)
		pfx.Withdraw(route.name, route.face)
	}
}

func (pfx *PrefixModule) activeFaceSnapshot() (map[uint64]struct{}, map[uint64]struct{}) {
	pfx.activeFacesMu.RLock()
	defer pfx.activeFacesMu.RUnlock()

	active := make(map[uint64]struct{}, len(pfx.activeFaces))
	for faceID := range pfx.activeFaces {
		active[faceID] = struct{}{}
	}
	seen := make(map[uint64]struct{}, len(pfx.seenFaces))
	for faceID := range pfx.seenFaces {
		seen[faceID] = struct{}{}
	}
	return active, seen
}

func (pfx *PrefixModule) startFaceEvents() {
	pfx.mu.Lock()
	if pfx.faceEventsStop != nil {
		pfx.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	pfx.faceEventsStop = stop
	pfx.faceEventsDone = done
	pfx.mu.Unlock()

	go pfx.runFaceEvents(stop, done)
}

func (pfx *PrefixModule) stopFaceEvents() {
	pfx.mu.Lock()
	stop := pfx.faceEventsStop
	done := pfx.faceEventsDone
	pfx.faceEventsStop = nil
	pfx.faceEventsDone = nil
	pfx.mu.Unlock()

	if stop != nil {
		close(stop)
	}
	if done != nil {
		<-done
	}
}

func (pfx *PrefixModule) runFaceEvents(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)

	var nextSeq uint64 = 0
	for {
		select {
		case <-stop:
			return
		default:
		}

		seq, notification, err := pfx.fetchFaceEvent(nextSeq)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}

			log.Warn(pfx, "Failed to fetch face event", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if notification == nil {
			continue
		}

		// If a gap appears (history rollover or startup race), discard local
		// face-state cache and rebuild state from subsequent events only.
		if nextSeq != 0 && seq > nextSeq {
			pfx.activeFacesMu.Lock()
			pfx.activeFaces = make(map[uint64]struct{})
			pfx.seenFaces = make(map[uint64]struct{})
			pfx.activeFacesMu.Unlock()
		}
		nextSeq = seq + 1
		pfx.applyFaceEvent(notification)
	}
}

func (pfx *PrefixModule) fetchFaceEvent(nextSeq uint64) (uint64, *mgmt.FaceEventNotification, error) {
	engine := pfx.client.Engine()
	if engine == nil {
		return 0, nil, fmt.Errorf("missing client engine")
	}

	base := enc.Name{
		enc.LOCALHOST,
		enc.NewGenericComponent("nfd"),
		enc.NewGenericComponent("faces"),
		enc.NewGenericComponent("events"),
	}
	name := base.Clone()
	if nextSeq > 0 {
		name = name.Append(enc.NewSequenceNumComponent(nextSeq))
	}

	cfg := &ndn.InterestConfig{
		CanBePrefix: true,
		MustBeFresh: true,
		Lifetime:    optional.Some(1 * time.Second),
		Nonce:       utils.ConvertNonce(engine.Timer().Nonce()),
	}
	interest, err := engine.Spec().MakeInterest(name, cfg, nil, nil)
	if err != nil {
		return 0, nil, err
	}

	ch := make(chan ndn.ExpressCallbackArgs, 1)
	if err := engine.Express(interest, func(args ndn.ExpressCallbackArgs) {
		select {
		case ch <- args:
		default:
		}
	}); err != nil {
		return 0, nil, err
	}

	args := <-ch
	switch args.Result {
	case ndn.InterestResultTimeout:
		return 0, nil, nil
	case ndn.InterestResultData:
		// continue below
	default:
		return 0, nil, fmt.Errorf("face event Interest failed: %s", args.Result)
	}

	dataName := args.Data.Name()
	if len(dataName) != len(base)+1 || !base.IsPrefix(dataName) || !dataName.At(-1).IsSequenceNum() {
		return 0, nil, fmt.Errorf("unexpected face event Data name: %s", dataName)
	}
	seq := dataName.At(-1).NumberVal()

	notification, err := mgmt.ParseFaceEventNotification(enc.NewWireView(args.Data.Content()), true)
	if err != nil || notification == nil || notification.Val == nil {
		if err == nil {
			err = fmt.Errorf("invalid face event notification")
		}
		return 0, nil, err
	}
	return seq, notification, nil
}

func (pfx *PrefixModule) applyFaceEvent(notification *mgmt.FaceEventNotification) {
	if notification == nil || notification.Val == nil {
		return
	}

	faceID := notification.Val.FaceId
	if faceID == 0 {
		return
	}

	pfx.activeFacesMu.Lock()
	defer pfx.activeFacesMu.Unlock()
	pfx.seenFaces[faceID] = struct{}{}

	switch notification.Val.FaceEventKind {
	case mgmt.FaceEventDestroyed:
		delete(pfx.activeFaces, faceID)
	case mgmt.FaceEventCreated, mgmt.FaceEventUp, mgmt.FaceEventDown:
		// Keep parity with /faces/list snapshot semantics (presence in FaceTable).
		pfx.activeFaces[faceID] = struct{}{}
	default:
		// Ignore unknown kinds.
	}
}
