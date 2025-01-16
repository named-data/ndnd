/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2022 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/fw"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/utils"
)

// ContentStoreModule is the module that handles Content Store Management.
type ContentStoreModule struct {
	manager *Thread
}

func (c *ContentStoreModule) String() string {
	return "mgmt-cs"
}

func (c *ContentStoreModule) registerManager(manager *Thread) {
	c.manager = manager
}

func (c *ContentStoreModule) getManager() *Thread {
	return c.manager
}

func (c *ContentStoreModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.Log.Warn(c, "Received CS management Interest from non-local source")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[len(LOCAL_PREFIX)+1].String()
	switch verb {
	case "config":
		c.config(interest)
	case "erase":
		// TODO
		//c.erase(interest)
	case "info":
		c.info(interest)
	default:
		core.Log.Warn(c, "Received Interest for non-existent verb", "verb", verb)
		c.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

func (c *ContentStoreModule) config(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		// Name not long enough to contain ControlParameters
		core.Log.Warn(c, "Missing ControlParameters", "name", interest.Name())
		c.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(c, interest)
	if params == nil {
		c.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if (params.Flags == nil && params.Mask != nil) || (params.Flags != nil && params.Mask == nil) {
		core.Log.Warn(c, "Flags and Mask fields must either both be present or both be not present")
		c.manager.sendCtrlResp(interest, 409, "ControlParameters are incorrect", nil)
		return
	}

	if params.Capacity != nil {
		core.Log.Info(c, "Setting CS capacity", "capacity", *params.Capacity)
		table.CfgSetCsCapacity(int(*params.Capacity))
	}

	if params.Mask != nil && params.Flags != nil {
		if *params.Mask&mgmt.CsEnableAdmit > 0 {
			val := *params.Flags&mgmt.CsEnableAdmit > 0
			core.Log.Info(c, "Setting CS admit flag", "value", val)
			table.CfgSetCsAdmit(val)
		}

		if *params.Mask&mgmt.CsEnableServe > 0 {
			val := *params.Flags&mgmt.CsEnableServe > 0
			core.Log.Info(c, "Setting CS serve flag", "value", val)
			table.CfgSetCsServe(val)
		}
	}

	c.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Capacity: utils.IdPtr(uint64(table.CfgCsCapacity())),
		Flags:    utils.IdPtr(c.getFlags()),
	})
}

func (c *ContentStoreModule) info(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	status := mgmt.CsInfoMsg{
		CsInfo: &mgmt.CsInfo{
			Capacity:   uint64(table.CfgCsCapacity()),
			Flags:      c.getFlags(),
			NCsEntries: 0,
		},
	}
	for threadID := 0; threadID < fw.CfgNumThreads(); threadID++ {
		thread := dispatch.GetFWThread(threadID)
		status.CsInfo.NCsEntries += uint64(thread.GetNumCsEntries())
	}

	name := LOCAL_PREFIX.Append(
		enc.NewStringComponent(enc.TypeGenericNameComponent, "cs"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "info"),
	)
	c.manager.sendStatusDataset(interest, name, status.Encode())
}

func (c *ContentStoreModule) getFlags() uint64 {
	flags := uint64(0)
	if table.CfgCsAdmit() {
		flags |= mgmt.CsEnableAdmit
	}
	if table.CfgCsServe() {
		flags |= mgmt.CsEnableServe
	}
	return flags
}
