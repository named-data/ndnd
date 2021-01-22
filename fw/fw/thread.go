/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import (
	"crypto/sha512"
	"encoding/binary"
	"strconv"

	"github.com/eric135/YaNFD/core"
	"github.com/eric135/YaNFD/dispatch"
	"github.com/eric135/YaNFD/ndn"
	"github.com/eric135/YaNFD/table"
)

// MaxFwThreads Maximum number of forwarding threads
const MaxFwThreads = 32

// Threads contains all forwarding threads
var Threads map[int]*Thread

// HashNameToFwThread hashes an NDN name to a forwarding thread.
func HashNameToFwThread(name *ndn.Name) int {
	sum := sha512.Sum512([]byte(name.String()))
	return int(binary.BigEndian.Uint64(sum[56:]) % uint64(len(Threads)))
}

// HashNameToAllPrefixFwThreads hahes an NDN name to all forwarding threads for all prefixes of the name.
func HashNameToAllPrefixFwThreads(name *ndn.Name) []int {
	threadMap := make(map[int]interface{})

	for i := name.Size(); i > 0; i++ {
		threadMap[HashNameToFwThread(name.Prefix(i))] = true
	}

	threadList := make([]int, 0, len(threadMap))
	for i := range threadMap {
		threadList = append(threadList, i)
	}
	return threadList
}

// Thread Represents a forwarding thread
type Thread struct {
	threadID         int
	pendingInterests chan *ndn.PendingPacket
	pendingDatas     chan *ndn.PendingPacket
	pitCS            *table.PitCsNode
	HasQuit          chan bool
}

// NewThread creates a new forwarding thread
func NewThread(id int) Thread {
	return Thread{
		threadID:         id,
		pendingInterests: make(chan *ndn.PendingPacket),
		pendingDatas:     make(chan *ndn.PendingPacket),
		HasQuit:          make(chan bool)}
}

func (t *Thread) String() string {
	return "FwThread-" + strconv.Itoa(t.threadID)
}

// GetID returns the ID of the forwarding thread
func (t *Thread) GetID() int {
	return t.GetID()
}

// Run forwarding thread
func (t *Thread) Run() {
	for !core.ShouldQuit {
		select {
		case pendingPacket := <-t.pendingInterests:
			t.processIncomingInterest(pendingPacket)
		case pendingPacket := <-t.pendingDatas:
			t.processIncomingData(pendingPacket)
		}
	}

	core.LogInfo(t, "Stopping thread")
	t.HasQuit <- true
}

// QueueInterest queues an Interest for processing by this forwarding thread.
func (t *Thread) QueueInterest(interest *ndn.PendingPacket) {
	t.pendingInterests <- interest
}

// QueueData queues a DAta packet for processing by this forwarding thread.
func (t *Thread) QueueData(data *ndn.PendingPacket) {
	t.pendingDatas <- data
}

func (t *Thread) processIncomingInterest(pendingPacket *ndn.PendingPacket) {
	// Ensure incoming face is indicated
	if pendingPacket.IncomingFaceID == nil {
		core.LogError(t, "Interest missing IncomingFaceId - DROP")
		return
	}

	// Extract Interest from PendingPacket
	interest, err := ndn.DecodeInterest(pendingPacket.Wire)
	if err != nil {
		core.LogInfo(t, "Unable to decode Interest packet - DROP")
		return
	}

	// Get incoming face
	incomingFace := dispatch.GetFace(int(*pendingPacket.IncomingFaceID))
	if incomingFace == nil {
		core.LogError(t, "Non-existent nexthop face "+strconv.Itoa(int(*pendingPacket.IncomingFaceID)))
	}

	core.LogTrace(t, "OnIncomingInterest: "+interest.Name().String()+", Face="+strconv.Itoa(incomingFace.FaceID()))

	// Check if violates /localhost
	if incomingFace.Scope() == ndn.NonLocal && interest.Name().Size() > 0 && interest.Name().At(0).String() == "localhost" {
		core.LogWarn(t, "Interest "+interest.Name().String()+" from non-local face="+strconv.FormatUint(*pendingPacket.IncomingFaceID, 10)+" violates /localhost scope - DROP")
		return
	}

	// Detect duplicate nonce by comparing against Dead Nonce List
	// TODO

	// Check for forwarding hint and, if present, determine if reaching producer region (and then strip forwarding hint)
	// TODO

	// Check if any matching PIT entries (and if duplicate)
	pitEntry, isDuplicate := t.pitCS.FindOrInsertPIT(interest, int(*pendingPacket.IncomingFaceID))
	if isDuplicate {
		// Interest loop - since we don't use Nacks, just drop
		core.LogInfo(t, "Interest "+interest.Name().String()+" is looping - DROP")
		return
	}

	// Add in-record and determine if already pending
	_, isAlreadyPending := pitEntry.FindOrInsertInRecord(interest, int(*pendingPacket.IncomingFaceID))
	if !isAlreadyPending {
		core.LogTrace(t, "Interest "+interest.Name().String()+" is not pending")

		// Check CS for matching entry
		csEntry := t.pitCS.FindMatchingDataCS(interest)
		if csEntry != nil {
			// Pass to strategy AfterContentStoreHit pipeline
			// TODO
			return
		}
	} else {
		core.LogTrace(t, "Interest "+interest.Name().String()+" is already pending")
	}

	// Otherwise, prepare to forward further
	// Create in-record
	pitEntry.FindOrInsertInRecord(interest, int(*pendingPacket.IncomingFaceID))

	// Update PIT entry expiration timer
	pitEntry.UpdateExpirationTimer()

	// If NextHopFaceId set, forward to that face (if it exists) or drop
	if pendingPacket.NextHopFaceID != nil {
		if dispatch.GetFace(int(*pendingPacket.NextHopFaceID)) != nil {
			core.LogTrace(t, "NextHopFaceId is set for Interest "+interest.Name().String()+" - dispatching directly to face")
			dispatch.GetFace(int(*pendingPacket.NextHopFaceID)).SendPacket(pendingPacket)
		} else {
			core.LogInfo(t, "Non-existent face specified in NextHopFaceId for Interest "+interest.Name().String()+" - DROP")
		}
		return
	}

	// Pass to strategy AfterContentStoreMiss pipeline
	// TODO
}

func (t *Thread) processOutgoingInterest(interest *ndn.Interest, nexthop int) {
	core.LogTrace(t, "OnOutgoingInterest: "+interest.Name().String()+", Face="+strconv.Itoa(nexthop))

	// Get outgoing face
	outgoingFace := dispatch.GetFace(nexthop)
	if outgoingFace == nil {
		core.LogError(t, "Non-existent nexthop face "+strconv.Itoa(nexthop))
	}

	// Send on outgoing face
	pendingPacket := new(ndn.PendingPacket)
	binary.BigEndian.PutUint16(pendingPacket.PitToken, uint16(t.threadID))
	var err error
	pendingPacket.Wire, err = interest.Encode()
	if err != nil {
		core.LogWarn(t, "Unable to encode Interest "+interest.Name().String()+" ("+err.Error()+" ) - DROP")
		return
	}
	outgoingFace.SendPacket(pendingPacket)
}

func (t *Thread) processIncomingData(pendingPacket *ndn.PendingPacket) {
	// Ensure incoming face is indicated
	if pendingPacket.IncomingFaceID == nil {
		core.LogError(t, "Data missing IncomingFaceId - DROP")
		return
	}

	// Extract Data from PendingPacket
	data, err := ndn.DecodeData(pendingPacket.Wire, false)
	if err != nil {
		core.LogInfo(t, "Unable to decode Data packet - DROP")
		return
	}

	// Get incoming face
	incomingFace := dispatch.GetFace(int(*pendingPacket.IncomingFaceID))
	if incomingFace == nil {
		core.LogError(t, "Non-existent nexthop face "+strconv.Itoa(int(*pendingPacket.IncomingFaceID)))
	}

	core.LogTrace(t, "OnIncomingData: "+data.Name().String()+", Face="+strconv.Itoa(incomingFace.FaceID()))

	// Check if violates /localhost
	if incomingFace.Scope() == ndn.NonLocal && data.Name().Size() > 0 && data.Name().At(0).String() == "localhost" {
		core.LogWarn(t, "Data "+data.Name().String()+" from non-local face="+strconv.FormatUint(*pendingPacket.IncomingFaceID, 10)+" violates /localhost scope - DROP")
		return
	}

	// Check for matching PIT entries
	pitEntries := t.pitCS.FindPITFromData(data)
	if len(pitEntries) == 0 {
		// Unsolicated Data - DROP
		// TODO: Add configuration option to accept these Data packets
		core.LogDebug(t, "Unsolicited Data "+data.Name().String()+" - DROP")
		return
	}

	// Add to Content Store
	t.pitCS.InsertDataCS(data)

	if len(pitEntries) == 1 {
		// Set PIT entry expiration to now
		pitEntries[0].SetExpirationTimerToNow()

		// Invoke strategy's AfterReceiveData
		// TODO

		// Mark PIT entry as satisfied
		// TODO - how do we do this?

		// Insert into dead nonce list (if needed)
		// TODO

		// Clear out records from PIT entry
		pitEntries[0].ClearOutRecords()
	} else {
		for _, pitEntry := range pitEntries {
			// Store all pending downstreams (except face Data packet arrived on) and PIT tokens
			downstreams := make(map[int][]byte)
			for downstreamFaceID, downstreamFaceRecord := range pitEntry.InRecords {
				if downstreamFaceID != int(*pendingPacket.IncomingFaceID) {
					// TODO: Ad-hoc faces
					downstreams[downstreamFaceID] = make([]byte, len(downstreamFaceRecord.PitToken))
					copy(downstreams[downstreamFaceID], downstreamFaceRecord.PitToken)
				}
			}

			// Set PIT entry expiration to now
			pitEntry.SetExpirationTimerToNow()

			// Invoke strategy's BeforeSatisfyInterest
			// TODO

			// Mark PIT entry as satisfied
			// TODO - how do we do this?

			// Insert into dead nonce list (if needed)
			// TODO

			// Clear PIT entry's in- and out-records
			pitEntry.ClearInRecords()
			pitEntry.ClearOutRecords()

			// Call outoing Data pipeline for each pending downstream
			for downstreamFaceID, downstreamPITToken := range downstreams {
				t.processOutgoingData(data, downstreamFaceID, downstreamPITToken)
			}
		}
	}
}

func (t *Thread) processOutgoingData(data *ndn.Data, nexthop int, pitToken []byte) {
	core.LogTrace(t, "OnOutgoingData: "+data.Name().String()+", Face="+strconv.Itoa(nexthop))

	// Get outgoing face
	outgoingFace := dispatch.GetFace(nexthop)
	if outgoingFace == nil {
		core.LogError(t, "Non-existent nexthop face "+strconv.Itoa(nexthop))
	}

	// Check if violates /localhost
	if outgoingFace.Scope() == ndn.NonLocal && data.Name().Size() > 0 && data.Name().At(0).String() == "localhost" {
		core.LogWarn(t, "Data "+data.Name().String()+" cannot be sent to non-local face="+strconv.Itoa(nexthop)+" since violates /localhost scope - DROP")
		return
	}

	// Send on outgoing face
	pendingPacket := new(ndn.PendingPacket)
	var err error
	if len(pitToken) > 0 {
		pendingPacket.PitToken = make([]byte, len(pitToken))
		copy(pendingPacket.PitToken, pitToken)
	}
	pendingPacket.Wire, err = data.Encode()
	if err != nil {
		core.LogWarn(t, "Unable to encode Data "+data.Name().String()+" ("+err.Error()+" ) - DROP")
		return
	}
	outgoingFace.SendPacket(pendingPacket)
}
