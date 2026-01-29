package dv

import (
	"time"

	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

// (AI GENERATED DESCRIPTION): Handles incoming management Interest packets by validating the prefix and routing them to the status or RIB handlers based on the command component.
func (dv *Router) mgmtOnInterest(args ndn.InterestHandlerArgs) {
	pfxLen := len(dv.config.MgmtPrefix())
	name := args.Interest.Name()
	if len(name) < pfxLen+1 {
		log.Warn(dv, "Invalid management Interest", "name", name)
		return
	}

	log.Trace(dv, "Received management Interest", "name", name)

	switch name[pfxLen].String() {
	case "status":
		dv.mgmtOnStatus(args)
	case "rib":
		dv.mgmtOnRib(args)
	default:
		log.Warn(dv, "Unknown management command", "name", name)
	}
}

// (AI GENERATED DESCRIPTION): Handles a status management Interest by replying with a Data packet that encodes the router’s current status (NDNd version, network and router names, and counts of RIB, neighbor, and FIB entries).
func (dv *Router) mgmtOnStatus(args ndn.InterestHandlerArgs) {
	status := func() tlv.Status {
		dv.mutex.Lock()
		defer dv.mutex.Unlock()
		return tlv.Status{
			Version:     utils.NDNdVersion,
			NetworkName: &tlv.Destination{Name: dv.config.NetworkName()},
			RouterName:  &tlv.Destination{Name: dv.config.RouterName()},
			NRibEntries: uint64(dv.rib.Size()),
			NNeighbors:  uint64(dv.neighbors.Size()),
			NFibEntries: uint64(dv.fib.Size()),
		}
	}()

	name := args.Interest.Name()
	cfg := &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeBlob),
		Freshness:   optional.Some(time.Second),
	}

	data, err := dv.engine.Spec().MakeData(name, cfg, status.Encode(), nil)
	if err != nil {
		log.Warn(dv, "Failed to make readvertise response Data", "err", err)
		return
	}

	args.Reply(data.Wire)
}

// Received advertisement Interest
func (dv *Router) mgmtOnRib(args ndn.InterestHandlerArgs) {
	res := &mgmt.ControlResponse{
		Val: &mgmt.ControlResponseVal{
			StatusCode: 400,
			StatusText: "Failed to execute command",
			Params:     nil,
		},
	}

	defer func() {
		signer := sig.NewSha256Signer()
		data, err := dv.engine.Spec().MakeData(
			args.Interest.Name(),
			&ndn.DataConfig{
				ContentType: optional.Some(ndn.ContentTypeBlob),
				Freshness:   optional.Some(1 * time.Second),
			},
			res.Encode(),
			signer)
		if err != nil {
			log.Warn(dv, "Failed to make readvertise response Data", "err", err)
			return
		}
		args.Reply(data.Wire)
	}()

	// /localhost/nlsr/rib/register/h%0C%07%07%08%05cathyo%01A/params-sha256=a971bb4753691b756cb58239e2585362a154ec6551985133990c8bd2401c466a
	// /localhost/nlsr/rib/unregister/h%0C%07%07%08%05cathyo%01A/params-sha256=026dd595c75032c5101b321fbc11eeb96277661c66bc0564ac7ea1a281ae8210
	iname := args.Interest.Name()
	if len(iname) != 6 {
		log.Warn(dv, "Invalid readvertise Interest", "name", iname)
		return
	}

	module, cmd, advC := iname[2], iname[3], iname[4]
	if module.String() != "rib" {
		log.Warn(dv, "Unknown readvertise module", "name", iname)
		return
	}

	params, err := mgmt.ParseControlParameters(enc.NewBufferView(advC.Val), false)
	if err != nil || params.Val == nil || params.Val.Name == nil {
		log.Warn(dv, "Failed to parse readvertised name", "err", err)
		return
	}

	name := params.Val.Name
	face := params.Val.FaceId.GetOr(0)
	cost := params.Val.Cost.GetOr(0)

	log.Debug(dv, "Received readvertise request", "cmd", cmd, "name", name)
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	switch cmd.String() {
	case "register":
		dv.pfx.Announce(name, face, cost)
	case "unregister":
		dv.pfx.Withdraw(name, face)
	default:
		log.Warn(dv, "Unknown readvertise cmd", "cmd", cmd)
		return
	}

	res.Val.StatusCode = 200
	res.Val.StatusText = "Readvertise command successful"
	res.Val.Params = &mgmt.ControlArgs{
		Name:   params.Val.Name,
		FaceId: optional.Some(uint64(1)), // NFD compatibility
		Origin: optional.Some(uint64(65)),
	}
}
