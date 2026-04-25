/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2026 Eric Newberry, Tianyuan Yu.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"encoding/json"

	"github.com/named-data/ndnd/fw/bier"
	"github.com/named-data/ndnd/fw/core"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

// BiftModule is the module that handles Bit Index Forwarding Table management.
type BiftModule struct {
	manager *Thread
}

func newBiftModule() *BiftModule {
	return &BiftModule{}
}

func (b *BiftModule) String() string {
	return "mgmt-bift"
}

func (b *BiftModule) registerManager(manager *Thread) {
	b.manager = manager
}

func (b *BiftModule) getManager() *Thread {
	return b.manager
}

func (b *BiftModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.Log.Warn(b, "Received BIFT management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[len(LOCAL_PREFIX)+1].String()
	switch verb {
	case "register":
		b.registerRouter(interest)
	case "rebuild":
		b.rebuild(interest)
	case "list":
		b.list(interest)
	default:
		b.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

func (b *BiftModule) registerRouter(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		b.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(b, interest)
	if params == nil {
		b.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		b.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}

	bfrId := params.Cost.GetOr(0)
	bier.Bift.RegisterRouter(params.Name, int(bfrId))
	core.Log.Info(b, "Registered BIFT router", "name", params.Name, "bfrId", bfrId)

	b.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name: params.Name,
		Cost: optional.Some(bfrId),
	})
}

func (b *BiftModule) rebuild(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		b.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	bier.Bift.BuildFromFib()
	core.Log.Info(b, "Rebuilt BIFT from FIB")

	b.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{})
}

func (b *BiftModule) list(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	status, err := json.Marshal(bier.Bift.Status())
	if err != nil {
		b.manager.sendCtrlResp(interest, 500, "Unable to encode BIFT status", nil)
		return
	}

	name := LOCAL_PREFIX.
		Append(enc.NewGenericComponent("bift")).
		Append(enc.NewGenericComponent("list"))
	b.manager.sendStatusDataset(interest, name, enc.Wire{status})
}
