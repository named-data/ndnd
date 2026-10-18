package dv

import (
	"time"

	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

// (AI GENERATED DESCRIPTION): Handles incoming management Interest packets by validating the prefix and routing them to the status or prefix handlers based on the command component.
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
	case "prefix":
		dv.mgmtOnPrefix(args)
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
			NPsdEntries: uint64(dv.pfx.EntryCount()),
		}
	}()

	name := args.Interest.Name()
	cfg := &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeBlob),
		Freshness:   optional.Some(time.Second),
	}

	data, err := dv.engine.Spec().MakeData(name, cfg, status.Encode(), nil)
	if err != nil {
		log.Warn(dv, "Failed to make status response Data", "err", err)
		return
	}

	args.Reply(data.Wire)
}

// Received prefix state Interest
func (dv *Router) mgmtOnPrefix(args ndn.InterestHandlerArgs) {
	const (
		cmdAnnounce = "announce"
		cmdList     = "list"
		cmdWithdraw = "withdraw"
	)

	interestName := args.Interest.Name()
	mgmtPrefixLen := len(dv.config.MgmtPrefix())

	if len(interestName) < mgmtPrefixLen+2 {
		log.Warn(dv, "Invalid prefix Interest", "name", interestName)
		return
	}

	if interestName[mgmtPrefixLen].String() != "prefix" {
		log.Warn(dv, "Unknown prefix module", "name", interestName)
		return
	}

	cmdName := interestName[mgmtPrefixLen+1].String()
	replyData := func(content enc.Wire, signer ndn.Signer, errMsg string) {
		cfg := &ndn.DataConfig{
			ContentType: optional.Some(ndn.ContentTypeBlob),
			Freshness:   optional.Some(1 * time.Second),
		}
		data, err := dv.engine.Spec().MakeData(args.Interest.Name(), cfg, content, signer)
		if err != nil {
			log.Warn(dv, errMsg, "err", err)
			return
		}
		args.Reply(data.Wire)
	}
	failureResponse := func() *mgmt.ControlResponse {
		return &mgmt.ControlResponse{
			Val: &mgmt.ControlResponseVal{
				StatusCode: 400,
				StatusText: "Failed to execute command",
				Params:     nil,
			},
		}
	}

	switch cmdName {
	case cmdList:
		if len(interestName) != mgmtPrefixLen+2 {
			log.Warn(dv, "Invalid prefix-list Interest", "name", interestName)
			return
		}

		status := makePrefixStateStatus(dv.pfx.SnapshotEntries())
		replyData(status.Encode(), nil, "Failed to make prefix-list response Data")
	case cmdAnnounce:
		if len(interestName) != mgmtPrefixLen+4 {
			log.Warn(dv, "Invalid prefix Interest", "name", interestName)
			return
		}

		res := failureResponse()
		defer func() {
			replyData(res.Encode(), sig.NewSha256Signer(), "Failed to make prefix response Data")
		}()

		argComp := interestName[mgmtPrefixLen+2]
		params, err := mgmt.ParseControlParameters(enc.NewBufferView(argComp.Val), false)
		if err != nil || params.Val == nil || params.Val.Name == nil {
			log.Warn(dv, "Failed to parse prefix args", "err", err)
			return
		}

		name := params.Val.Name
		log.Debug(dv, "Received prefix request", "cmd", cmdName, "name", name)

		faceID := uint64(0)
		if fid, ok := params.Val.FaceId.Get(); ok && fid != 0 {
			faceID = fid
		} else if args.IncomingFaceId.IsSet() {
			faceID = args.IncomingFaceId.Unwrap()
		}
		cost := params.Val.Cost.GetOr(0)
		if faceID == 0 {
			cost = 0
		}

		var validity *spec.ValidityPeriod
		responseParams := &mgmt.ControlArgs{
			Name: name,
			Cost: optional.Some(cost),
		}
		if faceID != 0 {
			responseParams.FaceId = optional.Some(faceID)
		}
		if expires, ok := params.Val.ExpirationPeriod.Get(); ok {
			if expires == 0 {
				res.Val.StatusText = "Prefix announce expires must be >0 (milliseconds)"
				log.Warn(dv, "Invalid prefix announce expires", "name", name, "status", res.Val.StatusText)
				return
			}

			maxExpirationMs := uint64((1<<63 - 1) / int64(time.Millisecond))
			if expires > maxExpirationMs {
				res.Val.StatusText = "Prefix announce expires is too large"
				log.Warn(dv, "Invalid prefix announce expires", "name", name, "status", res.Val.StatusText)
				return
			}

			validity = &spec.ValidityPeriod{
				NotAfter: time.Now().UTC().Add(time.Duration(expires) * time.Millisecond).Format(spec.TimeFmt),
			}
			responseParams.ExpirationPeriod = optional.Some(expires)
		}

		multicast := params.Val.Multicast
		dv.mutex.Lock()
		dv.pfx.Announce(name, faceID, cost, multicast, validity)
		dv.mutex.Unlock()

		res.Val.StatusCode = 200
		res.Val.StatusText = "Prefix state command successful"
		res.Val.Params = responseParams
	case cmdWithdraw:
		if len(interestName) != mgmtPrefixLen+4 {
			log.Warn(dv, "Invalid prefix Interest", "name", interestName)
			return
		}

		res := failureResponse()
		defer func() {
			replyData(res.Encode(), sig.NewSha256Signer(), "Failed to make prefix response Data")
		}()

		argComp := interestName[mgmtPrefixLen+2]
		params, err := mgmt.ParseControlParameters(enc.NewBufferView(argComp.Val), false)
		if err != nil || params.Val == nil || params.Val.Name == nil {
			log.Warn(dv, "Failed to parse prefix args", "err", err)
			return
		}

		name := params.Val.Name
		log.Debug(dv, "Received prefix request", "cmd", cmdName, "name", name)

		faceID := uint64(0)
		if fid, ok := params.Val.FaceId.Get(); ok && fid != 0 {
			faceID = fid
		} else if args.IncomingFaceId.IsSet() {
			faceID = args.IncomingFaceId.Unwrap()
		}

		dv.mutex.Lock()
		if faceID != 0 {
			dv.pfx.Withdraw(name, faceID)
		} else {
			dv.pfx.WithdrawRoute(name)
		}
		dv.mutex.Unlock()

		res.Val.StatusCode = 200
		res.Val.StatusText = "Prefix state command successful"
		res.Val.Params = &mgmt.ControlArgs{Name: name}
		if faceID != 0 {
			res.Val.Params.FaceId = optional.Some(faceID)
		}
	default:
		if len(interestName) != mgmtPrefixLen+4 {
			log.Warn(dv, "Invalid prefix Interest", "name", interestName)
			return
		}

		res := failureResponse()
		defer func() {
			replyData(res.Encode(), sig.NewSha256Signer(), "Failed to make prefix response Data")
		}()

		log.Warn(dv, "Unknown prefix cmd", "cmd", cmdName)
	}
}
