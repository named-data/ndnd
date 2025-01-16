package dv

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
)

// Received advertisement Interest
func (dv *Router) readvertiseOnInterest(args ndn.InterestHandlerArgs) {
	res := &mgmt.ControlResponse{
		Val: &mgmt.ControlResponseVal{
			StatusCode: 400,
			StatusText: "Failed to execute command",
			Params:     nil,
		},
	}

	defer func() {
		signer := security.NewSha256Signer()
		data, err := dv.engine.Spec().MakeData(
			args.Interest.Name(),
			&ndn.DataConfig{
				ContentType: utils.IdPtr(ndn.ContentTypeBlob),
				Freshness:   utils.IdPtr(1 * time.Second),
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
	// readvertise:  /localhost/nlsr/rib/unregister/h%0C%07%07%08%05cathyo%01A/params-sha256=026dd595c75032c5101b321fbc11eeb96277661c66bc0564ac7ea1a281ae8210
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

	params, err := mgmt.ParseControlParameters(enc.NewBufferReader(advC.Val), false)
	if err != nil || params.Val == nil || params.Val.Name == nil {
		log.Warn(dv, "Failed to parse readvertised name", "err", err)
		return
	}

	log.Debug(dv, "Received readvertise request", "cmd", cmd, "name", params.Val.Name)
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	switch cmd.String() {
	case "register":
		dv.pfx.Announce(params.Val.Name)
	case "unregister":
		dv.pfx.Withdraw(params.Val.Name)
	default:
		log.Warn(dv, "Unknown readvertise cmd", "cmd", cmd)
		return
	}

	res.Val.StatusCode = 200
	res.Val.StatusText = "Readvertise command successful"
	res.Val.Params = &mgmt.ControlArgs{
		Name:   params.Val.Name,
		FaceId: utils.IdPtr(uint64(1)), // NFD compatibility
		Origin: utils.IdPtr(uint64(65)),
		Cost:   utils.IdPtr(uint64(0)),
		Flags:  utils.IdPtr(uint64(0)),
	}
}
