/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/fw"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// ForwarderStatusModule is the module that provide forwarder status information.
type ForwarderStatusModule struct {
	manager                   *Thread
	nextGeneralDatasetVersion uint64
}

func (f *ForwarderStatusModule) String() string {
	return "ForwarderStatusMgmt"
}

func (f *ForwarderStatusModule) registerManager(manager *Thread) {
	f.manager = manager
}

func (f *ForwarderStatusModule) getManager() *Thread {
	return f.manager
}

func (f *ForwarderStatusModule) handleIncomingInterest(interest ndn.Interest, pitToken []byte, inFace uint64) {
	// Only allow from /localhost
	if !f.manager.localPrefix.IsPrefix(interest.Name()) {
		core.LogWarn(f, "Received forwarder status management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[f.manager.prefixLength()+1].String()
	switch verb {
	case "general":
		f.general(interest, pitToken, inFace)
	default:
		core.LogWarn(f, "Received Interest for non-existent verb '", verb, "'")
		response := makeControlResponse(501, "Unknown verb", nil)
		f.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}
}

func (f *ForwarderStatusModule) general(interest ndn.Interest, pitToken []byte, _ uint64) {
	if len(interest.Name()) > f.manager.prefixLength()+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	status := &mgmt.GeneralStatus{
		NfdVersion:       core.Version,
		StartTimestamp:   uint64(core.StartTimestamp.UnixNano() / 1000 / 1000),
		CurrentTimestamp: uint64(time.Now().UnixNano() / 1000 / 1000),
		NFibEntries:      uint64(len(table.FibStrategyTable.GetAllFIBEntries())),
	}
	// Don't set NNameTreeEntries because we don't use a NameTree
	for threadID := 0; threadID < fw.NumFwThreads; threadID++ {
		thread := dispatch.GetFWThread(threadID)
		status.NPitEntries += uint64(thread.GetNumPitEntries())
		status.NCsEntries += uint64(thread.GetNumCsEntries())
		status.NInInterests += thread.(*fw.Thread).NInInterests
		status.NInData += thread.(*fw.Thread).NInData
		status.NOutInterests += thread.(*fw.Thread).NOutInterests
		status.NOutData += thread.(*fw.Thread).NOutData
		status.NSatisfiedInterests += thread.(*fw.Thread).NSatisfiedInterests
		status.NUnsatisfiedInterests += thread.(*fw.Thread).NUnsatisfiedInterests
	}
	wire := status.Encode()

	name, _ := enc.NameFromStr(f.manager.localPrefix.String() + "/status/general")
	segments := makeStatusDataset(name, f.nextGeneralDatasetVersion, wire)
	f.manager.transport.Send(segments, pitToken, nil)

	core.LogTrace(f, "Published forwarder status dataset version=", f.nextGeneralDatasetVersion,
		", containing ", len(segments), " segments")
	f.nextGeneralDatasetVersion++
}
