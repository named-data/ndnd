/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/named-data/ndnd/fw/bier"
	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

type forwardPipeline int

const (
	fwUnicastTransit forwardPipeline = iota
	fwUnicastIngress
	fwUnicastEgress
	fwMulticastIngress
	fwMulticastEgress
	fwMulticastTransit
)

var forwardPipelineStrings = map[forwardPipeline]string{
	fwUnicastTransit:   "unicast-transit",
	fwUnicastIngress:   "unicast-ingress",
	fwUnicastEgress:    "unicast-egress",
	fwMulticastIngress: "multicast-ingress",
	fwMulticastEgress:  "multicast-egress",
	fwMulticastTransit: "multicast-transit",
}

func (p forwardPipeline) String() string {
	if s, ok := forwardPipelineStrings[p]; ok {
		return s
	}
	return fmt.Sprintf("forwardPipeline(%d)", int(p))
}

// pipelineContext holds arguments for pipeline handling functions
type pipelineContext struct {
	Pkt            *defn.Pkt
	PitEntry       table.PitEntry
	InFace         uint64
	Pipeline       forwardPipeline
	PetLocalHops   []*table.PetNextHop
	PetEntry       table.PetEntry
	PetFound       optional.Optional[bool]
	LookupName     enc.Name
	LocalFacesOnly bool
}

// nexthopFilterContext holds arguments for filterAllowedNexthops
type nexthopFilterContext struct {
	packet         *defn.Pkt
	inFace         uint64
	nextNet        []StrategyCandidateHop
	localFacesOnly bool
	pitEntry       table.PitEntry
}

// petLocalHopsContext holds arguments for collectPetLocalHops
type petLocalHopsContext struct {
	Packet     *defn.Pkt
	Pipeline   forwardPipeline
	LookupName enc.Name
	PitEntry   table.PitEntry
	PetEntry   table.PetEntry
	PetFound   optional.Optional[bool]
}

// forwardInContext holds arguments for tryContentStoreHit
type forwardInContext struct {
	Interest         *defn.FwInterest
	Packet           *defn.Pkt
	PitEntry         table.PitEntry
	Pipeline         forwardPipeline
	IsAlreadyPending bool
}

func (p forwardPipeline) isUnicast() bool {
	return p == fwUnicastTransit || p == fwUnicastIngress || p == fwUnicastEgress
}

func (p forwardPipeline) isMulticast() bool {
	return !p.isUnicast()
}

func (p forwardPipeline) isTransit() bool {
	return p == fwUnicastTransit || p == fwMulticastTransit
}

func (p forwardPipeline) isIngressEgress() bool {
	return !p.isTransit()
}

// MaxFwThreads Maximum number of forwarding threads
const MaxFwThreads = 32

// Threads contains all forwarding threads
var Threads []*Thread

// HashNameToFwThread hashes an NDN name to a forwarding thread.
func HashNameToFwThread(name enc.Name) int {
	// Dispatch all management requests to thread 0
	// this is fine, all it does is make sure the pitcs table in thread 0 has the management stuff.
	// This is not actually touching management.
	if len(name) > 0 && name[0].Equal(enc.LOCALHOST) {
		return 0
	}
	// to prevent negative modulos because we converted from uint to int
	return int(name.Hash() % uint64(len(Threads)))
}

// HashNameToAllPrefixFwThreads hashes an NDN name to all forwarding threads for all prefixes of the name.
// The return value is a boolean map of which threads match the name
func HashNameToAllPrefixFwThreads(name enc.Name) []bool {
	threads := make([]bool, len(Threads))

	// Dispatch all management requests to thread 0
	if len(name) > 0 && name[0].Equal(enc.LOCALHOST) {
		threads[0] = true
		return threads
	}

	prefixHash := name.PrefixHash()
	for i := 1; i < len(prefixHash); i++ {
		thread := int(prefixHash[i] % uint64(len(Threads)))
		threads[thread] = true
	}
	return threads
}

// Thread Represents a forwarding thread
type Thread struct {
	threadID      int
	pending       chan *defn.Pkt
	pitCS         table.PitCsTable
	strategies    map[uint64]Strategy
	deadNonceList *table.DeadNonceList
	shouldQuit    chan interface{}
	HasQuit       chan interface{}

	// Counters
	nInInterests          atomic.Uint64
	nInData               atomic.Uint64
	nOutInterests         atomic.Uint64
	nOutData              atomic.Uint64
	nSatisfiedInterests   atomic.Uint64
	nUnsatisfiedInterests atomic.Uint64
	nCsHits               atomic.Uint64
	nCsMisses             atomic.Uint64
}

// NewThread creates a new forwarding thread
func NewThread(id int) *Thread {
	t := new(Thread)
	t.threadID = id
	t.pending = make(chan *defn.Pkt, CfgFwQueueSize())
	t.pitCS = table.NewPitCS(t.finalizeInterest)
	t.strategies = InstantiateStrategies(t)
	t.deadNonceList = table.NewDeadNonceList()
	t.shouldQuit = make(chan interface{}, 1)
	t.HasQuit = make(chan interface{})
	return t
}

func (t *Thread) String() string {
	return fmt.Sprintf("fw-thread-%d", t.threadID)
}

// GetID returns the ID of the forwarding thread
func (t *Thread) GetID() int {
	return t.threadID
}

// Counters returns the counters for this forwarding thread
func (t *Thread) Counters() defn.FWThreadCounters {
	return defn.FWThreadCounters{
		NPitEntries:           t.pitCS.PitSize(),
		NCsEntries:            t.pitCS.CsSize(),
		NInInterests:          t.nInInterests.Load(),
		NInData:               t.nInData.Load(),
		NOutInterests:         t.nOutInterests.Load(),
		NOutData:              t.nOutData.Load(),
		NSatisfiedInterests:   t.nSatisfiedInterests.Load(),
		NUnsatisfiedInterests: t.nUnsatisfiedInterests.Load(),
		NCsHits:               t.nCsHits.Load(),
		NCsMisses:             t.nCsMisses.Load(),
	}
}

// TellToQuit tells the forwarding thread to quit
func (t *Thread) TellToQuit() {
	core.Log.Info(t, "Told to quit")
	t.shouldQuit <- true
}

// Run forwarding thread
func (t *Thread) Run() {
	if CfgLockThreadsToCores() {
		runtime.LockOSThread()
	}

	for !core.ShouldQuit {
		select {
		case pkt := <-t.pending:
			if pkt.L3.Interest != nil {
				t.processIncomingInterest(pkt)
			} else if pkt.L3.Data != nil {
				t.processIncomingData(pkt)
			}
		case <-t.deadNonceList.Ticker.C:
			t.deadNonceList.RemoveExpiredEntries()
		case <-t.pitCS.UpdateTicker():
			t.pitCS.Update()
		case <-t.shouldQuit:
			continue
		}
	}

	t.deadNonceList.Ticker.Stop()

	core.Log.Info(t, "Stopping thread")
	t.HasQuit <- true
}

// QueueInterest queues an Interest for processing by this forwarding thread.
func (t *Thread) QueueInterest(interest *defn.Pkt) {
	select {
	case t.pending <- interest:
	default:
		core.Log.Error(t, "Interest dropped due to full queue")
	}
}

// QueueData queues a Data packet for processing by this forwarding thread.
func (t *Thread) QueueData(data *defn.Pkt) {
	select {
	case t.pending <- data:
	default:
		core.Log.Error(t, "Data dropped due to full queue")
	}
}

func (t *Thread) processIncomingInterest(packet *defn.Pkt) {
	interest := packet.L3.Interest
	if interest == nil {
		panic("processIncomingInterest called with non-Interest packet")
	}

	incomingFace := dispatch.GetFace(packet.IncomingFaceID)
	if incomingFace == nil {
		core.Log.Error(t, "Interest has non-existent incoming face", "faceid", packet.IncomingFaceID, "name", packet.Name)
		return
	}

	if !t.validateHopLimitAndScope(interest, packet, incomingFace) {
		return
	}

	t.nInInterests.Add(1)

	fhName := t.processForwardingHint(interest)

	if !t.validateNonce(interest, packet) {
		return
	}

	pitEntry, isDuplicate := t.pitCS.InsertInterest(interest, fhName, incomingFace.FaceID())
	if isDuplicate {
		core.Log.Debug(t, "Interest is looping (PIT)", "name", packet.Name)
		return
	}

	lookupName := interest.Name()
	if fhName != nil {
		lookupName = fhName
	}

	pipeline, petEntry, petFound := t.determinePipeline(packet, lookupName)

	inRecord, isAlreadyPending, prevNonce := pitEntry.InsertInRecord(
		interest, incomingFace.FaceID(), packet.PitToken)

	if isAlreadyPending {
		core.Log.Trace(t, "Interest is already pending", "name", packet.Name)
		// Add the previous nonce to the dead nonce list to prevent further looping
		// TODO: review this design, not specified in NFD dev guide
		t.deadNonceList.Insert(interest.Name(), prevNonce)
	}

	if t.tryContentStoreHit(forwardInContext{
		Interest:         interest,
		Packet:           packet,
		PitEntry:         pitEntry,
		Pipeline:         pipeline,
		IsAlreadyPending: isAlreadyPending,
	}) {
		return
	}

	if inRecord.ExpirationTime.After(pitEntry.ExpirationTime()) {
		table.UpdateExpirationTimer(pitEntry, inRecord.ExpirationTime)
	}

	if t.tryNextHopForward(packet, pitEntry, incomingFace.FaceID()) {
		return
	}

	petLocalHops := t.collectPetLocalHops(petLocalHopsContext{
		Packet:     packet,
		Pipeline:   pipeline,
		LookupName: lookupName,
		PitEntry:   pitEntry,
		PetEntry:   petEntry,
		PetFound:   petFound,
	})
	localFacesOnly := incomingFace.Scope() != defn.Local && lookupName.At(0).Equal(enc.LOCALHOP)

	if pipeline.isUnicast() {
		t.handleUnicastPipeline(pipelineContext{
			Pkt:            packet,
			PitEntry:       pitEntry,
			InFace:         incomingFace.FaceID(),
			Pipeline:       pipeline,
			PetLocalHops:   petLocalHops,
			PetEntry:       petEntry,
			PetFound:       petFound,
			LookupName:     lookupName,
			LocalFacesOnly: localFacesOnly,
		})
		return
	}

	if pipeline.isMulticast() {
		t.handleMulticastPipeline(pipelineContext{
			Pkt:            packet,
			PitEntry:       pitEntry,
			InFace:         incomingFace.FaceID(),
			Pipeline:       pipeline,
			PetLocalHops:   petLocalHops,
			PetEntry:       petEntry,
			PetFound:       petFound,
			LookupName:     lookupName,
			LocalFacesOnly: localFacesOnly,
		})
	}
}

func (t *Thread) validateHopLimitAndScope(interest *defn.FwInterest, packet *defn.Pkt, incomingFace dispatch.Face) bool {
	if interest.HopLimitV != nil {
		core.Log.Trace(t, "HopLimit check", "name", packet.Name, "hoplimit", *interest.HopLimitV)
		if *interest.HopLimitV == 0 {
			return false
		}
		*interest.HopLimitV -= 1
	}

	core.Log.Trace(t, "OnIncomingInterest", "name", packet.Name, "faceid", incomingFace.FaceID(), "pittoken", len(packet.PitToken))

	// Check if violates /localhost
	if incomingFace.Scope() == defn.NonLocal && len(packet.Name) > 0 && packet.Name[0].Equal(enc.LOCALHOST) {
		core.Log.Warn(t, "Interest from non-local face violates /localhost scope", "name", packet.Name, "faceid", incomingFace.FaceID())
		return false
	}
	return true
}

func (t *Thread) processForwardingHint(interest *defn.FwInterest) enc.Name {
	hint := interest.ForwardingHintV
	if hint == nil || len(hint.Names) == 0 {
		return nil
	}

	isReachingProducerRegion := false
	var fhName enc.Name
	for _, fh := range hint.Names {
		if table.NetworkRegion.IsProducer(fh) {
			isReachingProducerRegion = true
			break
		} else if fhName == nil {
			fhName = fh
		}
	}
	if isReachingProducerRegion {
		return nil
	}
	return fhName
}

func (t *Thread) validateNonce(interest *defn.FwInterest, packet *defn.Pkt) bool {
	// Drop packet if no nonce is found
	if !interest.NonceV.IsSet() {
		core.Log.Debug(t, "Interest is missing Nonce", "name", packet.Name)
		return false
	}

	// Check if packet is in dead nonce list
	if exists := t.deadNonceList.Find(interest.NameV, interest.NonceV.Unwrap()); exists {
		core.Log.Debug(t, "Interest is looping (DNL)", "name", packet.Name, "nonce", interest.NonceV.Unwrap())
		return false
	}
	return true
}

func petLookupState(found optional.Optional[bool]) string {
	if !found.IsSet() {
		return "none"
	}
	if found.Unwrap() {
		return "true"
	}
	return "false"
}

func (t *Thread) ensurePetLookup(petEntry *table.PetEntry, petFound *optional.Optional[bool], lookupName enc.Name) {
	if petFound.IsSet() {
		return
	}
	entry, found := table.Pet.FindLongestPrefixEnc(lookupName)
	*petEntry = entry
	*petFound = optional.Some(found)
}

func (t *Thread) determinePipeline(packet *defn.Pkt, lookupName enc.Name) (forwardPipeline, table.PetEntry, optional.Optional[bool]) {
	var pipeline forwardPipeline
	var petEntry table.PetEntry
	petFound := optional.None[bool]()

	routerName, routerNameSet := CfgRouterName()

	if bier.IsBierEnabled() && len(packet.Bier) > 0 {
		if bier.BierGetBit(bier.BierClone(packet.Bier), bier.CfgBierIndex()) {
			pipeline = fwMulticastEgress
		} else {
			pipeline = fwMulticastTransit
		}
	} else if len(packet.EgressRouter) > 0 {
		if routerNameSet && (packet.EgressRouter.Equal(routerName) ||
			packet.EgressRouter.At(0).Equal(enc.LOCALHOP)) {
			pipeline = fwUnicastEgress
		} else {
			pipeline = fwUnicastTransit
		}
	} else {
		petEntry, found := table.Pet.FindLongestPrefixEnc(lookupName)
		petFound = optional.Some(found)
		if found && petEntry.Multicast {
			pipeline = fwMulticastIngress
		} else {
			pipeline = fwUnicastIngress
		}
	}

	isLocalHop := lookupName.At(0).Equal(enc.LOCALHOP)
	core.Log.Trace(t, "Interest pipeline decision",
		"name", packet.Name,
		"lookup", lookupName,
		"pipeline", pipeline,
		"petFound", petLookupState(petFound),
		"isLocalHop", isLocalHop,
		"egressRouter", len(packet.EgressRouter) > 0,
		"bier", len(packet.Bier) > 0,
	)

	return pipeline, petEntry, petFound
}

func (t *Thread) tryContentStoreHit(ctx forwardInContext) bool {
	if !ctx.Pipeline.isUnicast() || ctx.IsAlreadyPending || !t.pitCS.IsCsServing() {
		return false
	}

	csEntry := t.pitCS.FindMatchingDataFromCS(ctx.Interest)
	if csEntry == nil {
		t.nCsMisses.Add(1)
		return false
	}

	t.nCsHits.Add(1)

	csData, csWire, err := csEntry.Copy()
	if csData == nil || csWire == nil {
		if err != nil {
			core.Log.Error(t, "Error copying CS entry", "err", err)
		} else {
			core.Log.Error(t, "Error copying CS entry", "err", "csData is nil")
		}
		return false
	}

	table.UpdateExpirationTimer(ctx.PitEntry, time.Now())

	ctx.Packet.EgressRouter = nil
	ctx.Packet.L3.Data = csData
	ctx.Packet.L3.Interest = nil
	ctx.Packet.Raw = enc.Wire{csWire}
	ctx.Packet.Name = csData.NameV
	t.afterContentStoreHit(ctx.Packet, ctx.PitEntry, ctx.Packet.IncomingFaceID)
	return true
}

func (t *Thread) tryNextHopForward(packet *defn.Pkt, pitEntry table.PitEntry, inFace uint64) bool {
	hop, ok := packet.NextHopFaceID.Get()
	if !ok {
		return false
	}

	if face := dispatch.GetFace(hop); face != nil {
		core.Log.Trace(t, "NextHopFaceId is set for Interest", "name", packet.Name)
		t.processOutgoingInterest(packet, pitEntry, hop, inFace)
		return true
	}

	core.Log.Info(t, "Non-existent face specified in NextHopFaceId for Interest",
		"name", packet.Name, "faceid", hop)
	return true
}

func (t *Thread) collectPetLocalHops(ctx petLocalHopsContext) []*table.PetNextHop {
	if !ctx.Pipeline.isIngressEgress() {
		return nil
	}

	t.ensurePetLookup(&ctx.PetEntry, &ctx.PetFound, ctx.LookupName)
	if !ctx.PetFound.GetOr(false) {
		return nil
	}

	petLocalHops := make([]*table.PetNextHop, 0, len(ctx.PetEntry.NextHops))
	for i := range ctx.PetEntry.NextHops {
		nexthop := &ctx.PetEntry.NextHops[i]
		if nexthop.FaceID == ctx.Packet.IncomingFaceID {
			continue
		}
		if ctx.PitEntry.InRecords()[nexthop.FaceID] != nil {
			continue
		}
		petLocalHops = append(petLocalHops, nexthop)
	}
	return petLocalHops
}

func (t *Thread) handleUnicastPipeline(ctx pipelineContext) {
	isLocalHop := ctx.Pkt.Name.At(0).Equal(enc.LOCALHOP)
	core.Log.Trace(t, "Unicast pipeline",
		"name", ctx.Pkt.Name,
		"lookup", ctx.LookupName,
		"petFound", petLookupState(ctx.PetFound),
		"localHop", isLocalHop,
		"localFacesOnly", ctx.LocalFacesOnly,
	)

	if len(ctx.PetLocalHops) > 0 {
		core.Log.Trace(t, "Local Egress captures the Interest", "name", ctx.Pkt.Name)
		ctx.Pkt.EgressRouter = nil
		t.processOutgoingInterest(ctx.Pkt, ctx.PitEntry, ctx.PetLocalHops[0].FaceID, ctx.InFace)
		return
	}

	nextNet := t.collectNetworkNextHops(ctx.Pkt, ctx.PetEntry, ctx.PetFound)

	if len(nextNet) == 0 {
		core.Log.Trace(t, "Unicast forwarding: no PET and no FIB nexthops",
			"name", ctx.Pkt.Name,
			"lookup", ctx.LookupName,
			"pipeline", ctx.Pipeline,
			"isLocalHop", isLocalHop,
		)
	}

	allowedNetNexthops := t.filterAllowedNexthops(nexthopFilterContext{
		packet:         ctx.Pkt,
		inFace:         ctx.InFace,
		nextNet:        nextNet,
		localFacesOnly: ctx.LocalFacesOnly,
		pitEntry:       ctx.PitEntry,
	})

	if len(allowedNetNexthops) > 0 {
		core.Log.Trace(t, "Unicast forward",
			"name", ctx.Pkt.Name,
			"allowedNet", len(allowedNetNexthops),
			"localFacesOnly", ctx.LocalFacesOnly,
		)
		strategyName := table.FibStrategyTable.FindStrategyEnc(ctx.LookupName)
		strategy := t.strategies[strategyName.Hash()]
		strategy.AfterReceiveInterest(ctx.Pkt, ctx.PitEntry, ctx.InFace, allowedNetNexthops)
	}
}

func (t *Thread) collectNetworkNextHops(packet *defn.Pkt, petEntry table.PetEntry, petFound optional.Optional[bool]) []StrategyCandidateHop {
	var nextNet []StrategyCandidateHop

	if len(packet.EgressRouter) > 0 {
		for _, nextHop := range table.FibStrategyTable.FindNextHopsEnc(packet.EgressRouter) {
			nextNet = append(nextNet, StrategyCandidateHop{
				HopEntry:     nextHop,
				EgressRouter: packet.EgressRouter,
			})
		}
	} else if petFound.GetOr(false) {
		for _, er := range petEntry.EgressRouters {
			for _, nextHop := range table.FibStrategyTable.FindNextHopsEnc(er) {
				nextNet = append(nextNet, StrategyCandidateHop{
					HopEntry:     nextHop,
					EgressRouter: er,
				})
			}
		}
	}

	return nextNet
}

func (t *Thread) filterAllowedNexthops(ctx nexthopFilterContext) []StrategyCandidateHop {
	allowedNetNexthops := make([]StrategyCandidateHop, 0, len(ctx.nextNet))

	for _, nexthop := range ctx.nextNet {
		if nexthop.HopEntry.Nexthop == ctx.inFace {
			continue
		}

		if ctx.localFacesOnly {
			if face := dispatch.GetFace(nexthop.HopEntry.Nexthop); face != nil && face.Scope() != defn.Local {
				continue
			}
		}

		if ctx.pitEntry.InRecords()[nexthop.HopEntry.Nexthop] != nil {
			continue
		}

		allowedNetNexthops = append(allowedNetNexthops, nexthop)
	}

	return allowedNetNexthops
}

func (t *Thread) handleMulticastPipeline(ctx pipelineContext) {
	isLocalHop := ctx.LookupName.At(0).Equal(enc.LOCALHOP)
	core.Log.Trace(t, "Multicast pipeline",
		"name", ctx.Pkt.Name,
		"lookup", ctx.LookupName,
		"petFound", petLookupState(ctx.PetFound),
		"localHop", isLocalHop,
		"localFacesOnly", ctx.LocalFacesOnly,
		"bier", len(ctx.Pkt.Bier),
	)

	deliveredToLocal := false
	if len(ctx.PetLocalHops) > 0 {
		core.Log.Trace(t, "Local Egress captures the Interest", "name", ctx.Pkt.Name)
		for _, localHop := range ctx.PetLocalHops {
			ctx.Pkt.EgressRouter = nil
			t.processOutgoingInterest(ctx.Pkt, ctx.PitEntry, localHop.FaceID, ctx.InFace)
			deliveredToLocal = true
		}
	}

	if ctx.LocalFacesOnly {
		core.Log.Trace(t, "Multicast /localhop restricted to local faces",
			"name", ctx.Pkt.Name,
			"deliveredToLocal", deliveredToLocal,
		)
		return
	}

	// BIER forwarding for multicast
	t.ensurePetLookup(&ctx.PetEntry, &ctx.PetFound, ctx.LookupName)
	if !ctx.PetFound.GetOr(false) || len(ctx.PetEntry.EgressRouters) == 0 {
		return
	}

	// Encode BIER bitstring from PET egress routers if not present
	if len(ctx.Pkt.Bier) == 0 {
		ctx.Pkt.Bier = bier.Bift.BuildBierBitString(ctx.PetEntry.EgressRouters)
	}

	// Clear local bit if we already delivered locally
	if deliveredToLocal && len(ctx.Pkt.Bier) > 0 && bier.IsBierEnabled() {
		bs := bier.BierClone(ctx.Pkt.Bier)
		bier.BierClearBit(bs, bier.CfgBierIndex())
		ctx.Pkt.Bier = bs
		if bier.BierIsZero(bs) {
			return
		}
	}

	// Do BIER replication
	bierReplicate(t, ctx.Pkt, ctx.PitEntry, ctx.InFace, t.processOutgoingInterest)
}

func (t *Thread) afterContentStoreHit(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	inFace uint64,
) {
	core.Log.Trace(t, "AfterContentStoreHit", "name", packet.Name, "faceid", inFace)

	nexthop := inFace
	var pitToken []byte
	if inRecord, ok := pitEntry.InRecords()[nexthop]; ok {
		pitToken = inRecord.PitToken
		pitEntry.RemoveInRecord(nexthop)
	}
	t.processOutgoingData(packet, nexthop, pitToken, 0)
}

func (t *Thread) processOutgoingInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	nexthop uint64,
	inFace uint64,
) bool {
	interest := packet.L3.Interest
	if interest == nil {
		panic("processOutgoingInterest called with non-Interest packet")
	}

	core.Log.Trace(t, "OnOutgoingInterest", "name", packet.Name, "faceid", nexthop)

	// Get outgoing face
	outgoingFace := dispatch.GetFace(nexthop)
	if outgoingFace == nil {
		core.Log.Error(t, "Non-existent nexthop", "name", packet.Name, "faceid", nexthop)
		return false
	}
	if outgoingFace.FaceID() == inFace && outgoingFace.LinkType() != defn.AdHoc {
		core.Log.Debug(t, "Prevent send Interest back to incoming face", "name", packet.Name, "faceid", nexthop)
		return false
	}

	// Drop if HopLimit (if present) on Interest going to non-local face is 0. If so, drop
	if interest.HopLimitV != nil && int(*interest.HopLimitV) == 0 &&
		outgoingFace.Scope() == defn.NonLocal {
		core.Log.Debug(t, "Prevent send Interest with HopLimit=0 to non-local face", "name", packet.Name, "faceid", nexthop)
		return false
	}

	// Create or update out-record
	pitEntry.InsertOutRecord(interest, nexthop)

	// Update counters
	t.nOutInterests.Add(1)

	// Make new PIT token if needed
	pitToken := make([]byte, 6)
	binary.BigEndian.PutUint16(pitToken, uint16(t.threadID))
	binary.BigEndian.PutUint32(pitToken[2:], pitEntry.Token())

	// Send on outgoing face
	outgoingFace.SendPacket(dispatch.OutPkt{
		Pkt:      packet,
		PitToken: pitToken,
		InFace:   inFace,
	})

	return true
}

func (t *Thread) finalizeInterest(pitEntry table.PitEntry) {
	// Check for nonces to insert into dead nonce list
	for _, outRecord := range pitEntry.OutRecords() {
		t.deadNonceList.Insert(pitEntry.EncName(), outRecord.LatestNonce)
	}

	// Update counters
	if !pitEntry.Satisfied() {
		t.nUnsatisfiedInterests.Add(uint64(len(pitEntry.InRecords())))
	}
}

func (t *Thread) processIncomingData(packet *defn.Pkt) {
	data := packet.L3.Data
	if data == nil {
		panic("processIncomingData called with non-Data packet")
	}

	// Get PIT if present
	var pitToken *uint32
	//lint:ignore S1009 removing the nil check causes a segfault ¯\_(ツ)_/¯
	if packet.PitToken != nil && len(packet.PitToken) == 6 {
		pitToken = utils.IdPtr(binary.BigEndian.Uint32(packet.PitToken[2:6]))
	}

	// Get incoming face
	incomingFace := dispatch.GetFace(packet.IncomingFaceID)
	if incomingFace == nil {
		core.Log.Error(t, "Non-existent nexthop for Data", "name", packet.Name, "faceid", packet.IncomingFaceID)
		return
	}

	// Update counters
	t.nInData.Add(1)

	// Check if violates /localhost
	if incomingFace.Scope() == defn.NonLocal && len(packet.Name) > 0 && packet.Name[0].Equal(enc.LOCALHOST) {
		core.Log.Warn(t, "Data from non-local face violates /localhost scope", "name", packet.Name, "faceid", packet.IncomingFaceID)
		return
	}

	// Add to Content Store
	if t.pitCS.IsCsAdmitting() {
		t.pitCS.InsertData(data, packet.Raw.Join())
	}

	// Check for matching PIT entries
	pitEntries := t.pitCS.FindInterestPrefixMatchByDataEnc(data, pitToken)
	if len(pitEntries) == 0 {
		// Unsolicited Data - nothing more to do
		core.Log.Debug(t, "Unsolicited data", "name", packet.Name, "faceid", packet.IncomingFaceID)
		return
	}

	// Get strategy for name
	strategyName := table.FibStrategyTable.FindStrategyEnc(data.NameV)
	strategy := t.strategies[strategyName.Hash()]

	if len(pitEntries) == 1 {
		// When a single PIT entry matches, we pass the data to the strategy.
		// See alternative behavior for multiple matches below.
		pitEntry := pitEntries[0]

		// Set PIT entry expiration to now
		table.UpdateExpirationTimer(pitEntry, time.Now())

		// Invoke strategy's AfterReceiveData
		core.Log.Trace(t, "Sending Data", "name", packet.Name, "strategy", strategyName)
		strategy.AfterReceiveData(packet, pitEntry, packet.IncomingFaceID)

		// Mark PIT entry as satisfied
		pitEntry.SetSatisfied(true)

		// Insert into dead nonce list
		for _, outRecord := range pitEntry.OutRecords() {
			t.deadNonceList.Insert(data.NameV, outRecord.LatestNonce)
		}

		// Clear out records from PIT entry
		// TODO: NFD dev guide specifies in-records should not be cleared - why?
		pitEntry.ClearInRecords()
		pitEntry.ClearOutRecords()
	} else {
		// Multiple PIT entries can match when two interest have e.g. different flags
		// like CanBePrefix, or different forwarding hints. In this case, we send to all
		// downstream faces without consulting strategy (see NFD dev guide)
		for _, pitEntry := range pitEntries {
			// Store all pending downstreams (except face Data packet arrived on) and PIT tokens
			downstreams := make(map[uint64][]byte)
			for face, record := range pitEntry.InRecords() {
				if face != packet.IncomingFaceID {
					// TODO: Ad-hoc faces
					downstreams[face] = make([]byte, len(record.PitToken))
					copy(downstreams[face], record.PitToken)
				}
			}

			// Set PIT entry expiration to now
			table.UpdateExpirationTimer(pitEntry, time.Now())

			// Invoke strategy's BeforeSatisfyInterest
			strategy.BeforeSatisfyInterest(pitEntry, packet.IncomingFaceID)

			// Mark PIT entry as satisfied
			pitEntry.SetSatisfied(true)

			// Insert into dead nonce list
			for _, outRecord := range pitEntries[0].OutRecords() {
				t.deadNonceList.Insert(data.NameV, outRecord.LatestNonce)
			}

			// Clear PIT entry's in- and out-records
			pitEntry.ClearInRecords()
			pitEntry.ClearOutRecords()

			// Call outgoing Data pipeline for each pending downstream
			for face, token := range downstreams {
				core.Log.Trace(t, "Multiple PIT entries for Data", "name", packet.Name)
				t.processOutgoingData(packet, face, token, packet.IncomingFaceID)
			}
		}
	}
}

func (t *Thread) processOutgoingData(
	packet *defn.Pkt,
	nexthop uint64,
	pitToken []byte,
	inFace uint64,
) {
	data := packet.L3.Data
	if data == nil {
		panic("processOutgoingData called with non-Data packet")
	}

	core.Log.Trace(t, "OnOutgoingData", "name", packet.Name, "faceid", nexthop)

	// Get outgoing face
	outgoingFace := dispatch.GetFace(nexthop)
	if outgoingFace == nil {
		core.Log.Error(t, "Non-existent nexthop for Data", "name", packet.Name, "faceid", nexthop)
		return
	}

	// Check if violates /localhost
	if outgoingFace.Scope() == defn.NonLocal && len(packet.Name) > 0 && packet.Name[0].Equal(enc.LOCALHOST) {
		core.Log.Warn(t, "Data cannot be sent to non-local face since violates /localhost scope", "name", packet.Name, "faceid", nexthop)
		return
	}

	// Update counters
	t.nOutData.Add(1)
	t.nSatisfiedInterests.Add(1)

	// Send on outgoing face
	outgoingFace.SendPacket(dispatch.OutPkt{
		Pkt:      packet,
		PitToken: pitToken,
		InFace:   inFace,
	})
}
