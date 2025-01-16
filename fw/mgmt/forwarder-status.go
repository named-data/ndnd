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
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// ForwarderStatusModule is the module that provide forwarder status information.
type ForwarderStatusModule struct {
	manager *Thread
}

func (f *ForwarderStatusModule) String() string {
	return "mgmt-status"
}

func (f *ForwarderStatusModule) registerManager(manager *Thread) {
	f.manager = manager
}

func (f *ForwarderStatusModule) getManager() *Thread {
	return f.manager
}

func (f *ForwarderStatusModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.Log.Warn(f, "Received forwarder status management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[len(LOCAL_PREFIX)+1].String()
	switch verb {
	case "general":
		f.general(interest)
	default:
		f.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

func (f *ForwarderStatusModule) general(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	status := &mgmt.GeneralStatus{
		NfdVersion:       core.Version,
		StartTimestamp:   time.Duration(core.StartTimestamp.UnixNano()),
		CurrentTimestamp: time.Duration(time.Now().UnixNano()),
		NFibEntries:      uint64(len(table.FibStrategyTable.GetAllFIBEntries())),
	}
	// Don't set NNameTreeEntries because we don't use a NameTree
	for threadID := 0; threadID < fw.CfgNumThreads(); threadID++ {
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

	name := LOCAL_PREFIX.Append(
		enc.NewStringComponent(enc.TypeGenericNameComponent, "status"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "general"),
	)
	f.manager.sendStatusDataset(interest, name, status.Encode())
}
