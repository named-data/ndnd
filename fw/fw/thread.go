/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import (
	"encoding/binary"
	"runtime"
	"strconv"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/utils"
)

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
	threadID         int
	pendingInterests chan *defn.Pkt
	pendingDatas     chan *defn.Pkt
	pitCS            table.PitCsTable
	strategies       map[uint64]Strategy
	deadNonceList    *table.DeadNonceList
	shouldQuit       chan interface{}
	HasQuit          chan interface{}

	// Counters
	NInInterests          uint64
	NInData               uint64
	NOutInterests         uint64
	NOutData              uint64
	NSatisfiedInterests   uint64
	NUnsatisfiedInterests uint64
}

// NewThread creates a new forwarding thread
func NewThread(id int) *Thread {
	t := new(Thread)
	t.threadID = id
	t.pendingInterests = make(chan *defn.Pkt, fwQueueSize)
	t.pendingDatas = make(chan *defn.Pkt, fwQueueSize)
	t.pitCS = table.NewPitCS(t.finalizeInterest)
	t.strategies = InstantiateStrategies(t)
	t.deadNonceList = table.NewDeadNonceList()
	t.shouldQuit = make(chan interface{}, 1)
	t.HasQuit = make(chan interface{})
	return t
}

func (t *Thread) String() string {
	return "FwThread-" + strconv.Itoa(t.threadID)
}

// GetID returns the ID of the forwarding thread
func (t *Thread) GetID() int {
	return t.threadID
}

// GetNumPitEntries returns the number of entries in this thread's PIT.
func (t *Thread) GetNumPitEntries() int {
	return t.pitCS.PitSize()
}

// GetNumCsEntries returns the number of entries in this thread's ContentStore.
func (t *Thread) GetNumCsEntries() int {
	return t.pitCS.CsSize()
}

// TellToQuit tells the forwarding thread to quit
func (t *Thread) TellToQuit() {
	core.LogInfo(t, "Told to quit")
	t.shouldQuit <- true
}

// Run forwarding thread
func (t *Thread) Run() {
	if lockThreadsToCores {
		runtime.LockOSThread()
	}

	pitUpdateTimer := t.pitCS.UpdateTimer()
	for !core.ShouldQuit {
		select {
		case pendingPacket := <-t.pendingInterests:
			t.processIncomingInterest(pendingPacket)
		case pendingPacket := <-t.pendingDatas:
			t.processIncomingData(pendingPacket)
		case <-t.deadNonceList.Ticker.C:
			t.deadNonceList.RemoveExpiredEntries()
		case <-pitUpdateTimer:
			t.pitCS.Update()
		case <-t.shouldQuit:
			continue
		}
	}

	t.deadNonceList.Ticker.Stop()

	core.LogInfo(t, "Stopping thread")
	t.HasQuit <- true
}

// QueueInterest queues an Interest for processing by this forwarding thread.
func (t *Thread) QueueInterest(interest *defn.Pkt) {
	select {
	case t.pendingInterests <- interest:
	default:
		core.LogError(t, "Interest dropped due to full queue")
	}
}

// QueueData queues a Data packet for processing by this forwarding thread.
func (t *Thread) QueueData(data *defn.Pkt) {
	select {
	case t.pendingDatas <- data:
	default:
		core.LogError(t, "Data dropped due to full queue")
	}
}

func (t *Thread) processIncomingInterest(packet *defn.Pkt) {
	interest := packet.L3.Interest
	if interest == nil {
		panic("processIncomingInterest called with non-Interest packet")
	}

	// Already asserted that this is an Interest in link service
	// Get incoming face
	incomingFace := dispatch.GetFace(packet.IncomingFaceID)
	if incomingFace == nil {
		core.LogError(t, "Non-existent incoming FaceID=", packet.IncomingFaceID,
			" for Interest=", packet.Name, " - DROP")
		return
	}

	if interest.HopLimit() != nil {
		core.LogTrace(t, "Interest ", packet.Name, " has HopLimit=", *interest.HopLimit())
		if *interest.HopLimit() == 0 {
			return
		}
		*interest.HopLimit() -= 1
	}

	// Log PIT token (if any)
	if core.HasTraceLogs() {
		core.LogTrace(t, "OnIncomingInterest: ", packet.Name, ", FaceID=", incomingFace.FaceID(), ", PitTokenL=", len(packet.PitToken))
	}

	// Check if violates /localhost
	if incomingFace.Scope() == defn.NonLocal && len(packet.Name) > 0 && packet.Name[0].Equal(enc.LOCALHOST) {
		core.LogWarn(t, "Interest ", packet.Name, " from non-local face=", incomingFace.FaceID(), " violates /localhost scope - DROP")
		return
	}

	t.NInInterests++

	// Check for forwarding hint and, if present, determine if reaching producer region (and then strip forwarding hint)
	isReachingProducerRegion := true
	var fhName enc.Name = nil
	hint := interest.ForwardingHint()
	if hint != nil && len(hint) > 0 {
		isReachingProducerRegion = false
		for _, fh := range hint {
			if table.NetworkRegion.IsProducer(fh) {
				isReachingProducerRegion = true
				break
			} else if fhName == nil {
				fhName = fh
			}
		}
		if isReachingProducerRegion {
			// TODO: Drop the forwarding hint for now.
			// No way without re-encoding Interest for now.
			fhName = nil
		}
	}

	// Drop packet if no nonce is found
	if interest.Nonce() == nil {
		if core.HasDebugLogs() {
			core.LogDebug(t, "Interest ", packet.Name, " is missing Nonce - DROP")
		}
		return
	}

	// Check if packet is in dead nonce list
	if exists := t.deadNonceList.Find(interest.Name(), *interest.Nonce()); exists {
		if core.HasDebugLogs() {
			core.LogDebug(t, "Interest ", packet.Name, " is dropped by DeadNonce: ", *interest.Nonce())
		}
		return
	}

	// Check if any matching PIT entries (and if duplicate)
	// read into this, looks like this one will have to be manually changed
	pitEntry, isDuplicate := t.pitCS.InsertInterest(interest, fhName, incomingFace.FaceID())
	if isDuplicate {
		// Interest loop - since we don't use Nacks, just drop
		if core.HasDebugLogs() {
			core.LogDebug(t, "Interest ", packet.Name, " is looping - DROP")
		}
		return
	}

	// Get strategy for name
	strategyName := table.FibStrategyTable.FindStrategyEnc(interest.Name())
	strategy := t.strategies[strategyName.Hash()]

	// Add in-record and determine if already pending
	// this looks like custom interest again, but again can be changed without much issue?
	_, isAlreadyPending, prevNonce := pitEntry.InsertInRecord(
		interest, incomingFace.FaceID(), packet.PitToken)

	if !isAlreadyPending {
		core.LogTrace(t, "Interest ", packet.Name, " is not pending")

		// Check CS for matching entry
		if t.pitCS.IsCsServing() {
			csEntry := t.pitCS.FindMatchingDataFromCS(interest)
			if csEntry != nil {
				// Parse the cached data packet and replace in the pending one
				// This is not the fastest way to do it, but simplifies everything
				// significantly. We can optimize this later.
				csData, csWire, err := csEntry.Copy()
				if csData != nil && csWire != nil {
					packet.L3.Data = csData
					packet.L3.Interest = nil
					packet.Raw = csWire
					packet.Name = csData.Name()
					strategy.AfterContentStoreHit(packet, pitEntry, incomingFace.FaceID())
					return
				} else if err != nil {
					core.LogError(t, "Error copying CS entry: ", err)
				} else {
					core.LogError(t, "Error copying CS entry: csData is nil")
				}

			}
		}
	} else {
		if core.HasTraceLogs() {
			core.LogTrace(t, "Interest ", packet.Name, " is already pending")
		}

		// Add the previous nonce to the dead nonce list to prevent further looping
		// TODO: review this design, not specified in NFD dev guide
		t.deadNonceList.Insert(interest.Name(), prevNonce)
		t.deadNonceList.Insert(interest.Name(), prevNonce)
	}

	// Update PIT entry expiration timer
	table.UpdateExpirationTimer(pitEntry)

	// If NextHopFaceId set, forward to that face (if it exists) or drop
	if packet.NextHopFaceID != nil {
		if face := dispatch.GetFace(*packet.NextHopFaceID); face != nil {
			if core.HasTraceLogs() {
				core.LogTrace(t, "NextHopFaceId is set for Interest ", packet.Name, " - dispatching directly to face")
			}
			face.SendPacket(dispatch.OutPkt{
				Pkt:      packet,
				PitToken: packet.PitToken, // TODO: ??
				InFace:   packet.IncomingFaceID,
			})
		} else {
			core.LogInfo(t, "Non-existent face specified in NextHopFaceId for Interest ", packet.Name, " - DROP")
		}
		return
	}

	// Use forwarding hint if present
	lookupName := interest.Name()
	if fhName != nil {
		lookupName = fhName
	}

	// Query the FIB for all possible nexthops
	nexthops := table.FibStrategyTable.FindNextHopsEnc(lookupName)

	// If the first component is /localhop, we do not forward interests received
	// on non-local faces to non-local faces
	localFacesOnly := incomingFace.Scope() != defn.Local && len(packet.Name) > 0 && packet.Name[0].Equal(enc.LOCALHOP)

	// Filter the nexthops that are allowed for this Interest
	allowedNexthops := [defn.MaxNextHops]*table.FibNextHopEntry{}
	allowedNexthopsCount := 0
	for _, nexthop := range nexthops {
		// Exclude non-local faces for localhop enforcement
		if localFacesOnly {
			if face := dispatch.GetFace(nexthop.Nexthop); face != nil && face.Scope() != defn.Local {
				continue
			}
		}

		// Exclude faces that have an in-record for this interest
		// TODO: unclear where NFD dev guide specifies such behavior (if any)
		record := pitEntry.InRecords()[nexthop.Nexthop]
		if record == nil || nexthop.Nexthop == incomingFace.FaceID() {
			allowedNexthops[allowedNexthopsCount] = nexthop
			allowedNexthopsCount++
		}
		if allowedNexthopsCount >= defn.MaxNextHops {
			break // limit reached
		}
	}

	// Pass to strategy AfterReceiveInterest pipeline
	strategy.AfterReceiveInterest(
		packet, pitEntry, incomingFace.FaceID(),
		allowedNexthops, allowedNexthopsCount)
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

	core.LogTrace(t, "OnOutgoingInterest: ", packet.Name, ", FaceID=", nexthop)

	// Get outgoing face
	outgoingFace := dispatch.GetFace(nexthop)
	if outgoingFace == nil {
		core.LogError(t, "Non-existent nexthop FaceID=", nexthop, " for Interest=", packet.Name, " - DROP")
		return false
	}
	if outgoingFace.FaceID() == inFace && outgoingFace.LinkType() != defn.AdHoc {
		core.LogDebug(t, "Attempting to send Interest=", packet.Name, " back to incoming face - DROP")
		return false
	}

	// Drop if HopLimit (if present) on Interest going to non-local face is 0. If so, drop
	if interest.HopLimit() != nil && int(*interest.HopLimit()) == 0 &&
		outgoingFace.Scope() == defn.NonLocal {
		core.LogDebug(t, "Attempting to send Interest=", packet.Name, " with HopLimit=0 to non-local face - DROP")
		return false
	}

	// Create or update out-record
	pitEntry.InsertOutRecord(interest, nexthop)

	t.NOutInterests++

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

	// Counters
	if !pitEntry.Satisfied() {
		t.NUnsatisfiedInterests += uint64(len(pitEntry.InRecords()))
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
		core.LogError(t, "Non-existent nexthop FaceID=", packet.IncomingFaceID, " for Data=", packet.Name, " DROP")
		return
	}

	t.NInData++

	// Check if violates /localhost
	if incomingFace.Scope() == defn.NonLocal && len(packet.Name) > 0 && packet.Name[0].Equal(enc.LOCALHOST) {
		core.LogWarn(t, "Data ", packet.Name, " from non-local FaceID=", packet.IncomingFaceID, " violates /localhost scope - DROP")
		return
	}

	// Add to Content Store
	if t.pitCS.IsCsAdmitting() {
		t.pitCS.InsertData(data, packet.Raw)
	}

	// Check for matching PIT entries
	pitEntries := t.pitCS.FindInterestPrefixMatchByDataEnc(data, pitToken)
	if len(pitEntries) == 0 {
		// Unsolicited Data - nothing more to do
		core.LogDebug(t, "Unsolicited data ", packet.Name, " FaceID=", packet.IncomingFaceID, " - DROP")
		core.LogDebug(t, "Unsolicited data ", packet.Name, " FaceID=", packet.IncomingFaceID, " - DROP")
		return
	}

	// Get strategy for name
	strategyName := table.FibStrategyTable.FindStrategyEnc(data.Name())
	strategy := t.strategies[strategyName.Hash()]

	if len(pitEntries) == 1 {
		// When a single PIT entry matches, we pass the data to the strategy.
		// See alternative behavior for multiple matches below.
		pitEntry := pitEntries[0]

		// Set PIT entry expiration to now
		table.SetExpirationTimerToNow(pitEntry)

		// Invoke strategy's AfterReceiveData
		core.LogTrace(t, "Sending Data=", packet.Name, " to strategy=", strategyName)
		strategy.AfterReceiveData(packet, pitEntry, packet.IncomingFaceID)

		// Mark PIT entry as satisfied
		pitEntry.SetSatisfied(true)

		// Insert into dead nonce list
		for _, outRecord := range pitEntry.OutRecords() {
			t.deadNonceList.Insert(data.Name(), outRecord.LatestNonce)
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
			table.SetExpirationTimerToNow(pitEntry)

			// Invoke strategy's BeforeSatisfyInterest
			strategy.BeforeSatisfyInterest(pitEntry, packet.IncomingFaceID)

			// Mark PIT entry as satisfied
			pitEntry.SetSatisfied(true)

			// Insert into dead nonce list
			for _, outRecord := range pitEntries[0].GetOutRecords() {
				t.deadNonceList.Insert(data.Name(), outRecord.LatestNonce)
			}

			// Clear PIT entry's in- and out-records
			pitEntry.ClearInRecords()
			pitEntry.ClearOutRecords()

			// Call outgoing Data pipeline for each pending downstream
			for face, token := range downstreams {
				core.LogTrace(t, "Multiple PIT entries Data=", packet.Name)
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

	core.LogTrace(t, "OnOutgoingData: ", packet.Name, ", FaceID=", nexthop)

	// Get outgoing face
	outgoingFace := dispatch.GetFace(nexthop)
	if outgoingFace == nil {
		core.LogError(t, "Non-existent nexthop FaceID=", nexthop, " for Data=", packet.Name, " - DROP")
		return
	}

	// Check if violates /localhost
	if outgoingFace.Scope() == defn.NonLocal && len(packet.Name) > 0 && packet.Name[0].Equal(enc.LOCALHOST) {
		core.LogWarn(t, "Data ", packet.Name, " cannot be sent to non-local FaceID=", nexthop, " since violates /localhost scope - DROP")
		return
	}

	t.NOutData++
	t.NSatisfiedInterests++

	// Send on outgoing face
	outgoingFace.SendPacket(dispatch.OutPkt{
		Pkt:      packet,
		PitToken: pitToken,
		InFace:   inFace,
	})
}
