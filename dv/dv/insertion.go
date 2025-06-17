package dv

import (
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

func (dv *Router) onInsertion(args ndn.InterestHandlerArgs) {
	resError := &mgmt.ControlResponse{
		Val: &mgmt.ControlResponseVal{
			StatusCode: 400,
			StatusText: "Failed to execute prefix insertion",
			Params:     nil,
		},
	}

	reply := func(res *mgmt.ControlResponse) {
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
			log.Warn(dv, "Failed to make Prefix Insertion response Data", "err", err)
			return
		}
		args.Reply(data.Wire)
	}

	// If there is no incoming face ID, we can't use this
	if !args.IncomingFaceId.IsSet() {
		log.Warn(dv, "Received Prefix Insertion with no incoming face ID, ignoring")
		reply(resError)
		return
	}

	// Check if app param is present
	if args.Interest.AppParam() == nil {
		log.Warn(dv, "Received Prefix Insertion with no AppParam, ignoring")
		reply(resError)
		return
	}

	paParams, err := tlv.ParsePrefixInsertion(enc.NewWireView(args.Interest.AppParam()), true)
	if err != nil {
		log.Warn(dv, "Failed to parse Prefix Insertion AppParam", "err", err)
		reply(resError)
		return
	}

	// Decode Prefix Announcement Object
	dCtx := spec.DataParsingContext{}
	dCtx.Init()
	data, err := dCtx.Parse(enc.NewBufferView(paParams.Data), true)
	if err != nil {
		log.Warn(dv, "Failed to parse Prefix Insertion inner data", "err", err)
		reply(resError)
		return
	}
	sigCov := dCtx.SigCovered()

	var stapledCertCallbacks []ndn.ExpressCallbackArgs
	for _, certWire := range paParams.StapledCertificates {
		data, sigCov, err := spec.Spec{}.ReadData(enc.NewBufferView(certWire))
		if err != nil {
			log.Warn(dv, "Stapled malformed certificate", "err", err)
			reply(resError)
			return
		}

		stapledCertCallbacks = append(stapledCertCallbacks,
			ndn.ExpressCallbackArgs{
				Result:     ndn.InterestResultData,
				Data:       data,
				RawData:    enc.Wire{certWire},
				SigCovered: sigCov,
				IsLocal:    true,
			})
	}

	// Validate signature
	dv.prefixInsertionClient.ValidateExt(ndn.ValidateExtArgs{
		Data:       data,
		SigCovered: sigCov,
		Fetch: optional.Some(func(name enc.Name, config *ndn.InterestConfig, callback ndn.ExpressCallbackFunc) {
			for _, certCallback := range stapledCertCallbacks {
				if certCallback.Data.Name().Equal(name) {
					dv.prefixInsertionClient.Engine().Post(func() {
						callback(certCallback)
					})
					return
				}
			}

			config.NextHopId = optional.None[uint64]()
			dv.prefixInsertionClient.ExpressR(ndn.ExpressRArgs{
				Name:     name,
				Config:   config,
				Retries:  3,
				Callback: callback,
				TryStore: dv.prefixInsertionClient.Store(),
			})
		}),
		Callback: func(valid bool, err error) {
			if !valid || err != nil {
				log.Warn(dv, "Failed to validate signature", "name", data.Name(), "valid", valid, "err", err)
				reply(resError)
				return
			}

			res := dv.onPrefixInsertionObject(data, args.IncomingFaceId.Unwrap())
			reply(res)
		},
	})
}

func (dv *Router) onPrefixInsertionObject(object ndn.Data, faceId uint64) *mgmt.ControlResponse {
	resError := &mgmt.ControlResponse{
		Val: &mgmt.ControlResponseVal{
			StatusCode: 400,
			StatusText: "Failed to execute prefix insertion",
			Params:     nil,
		},
	}

	if contentType, set := object.ContentType().Get(); !set || contentType != ndn.ContentTypePrefixAnnouncement {
		log.Warn(dv, "Prefix Announcement Object does not have the correct content type",
			"contentType", object.ContentType())
		return resError
	}

	var prefix enc.Name
	found := false
	var version uint64

	for i, c := range object.Name() {
		if c.IsKeyword("PA") {
			if len(object.Name()) != i+3 ||
				!object.Name().At(i+1).IsVersion() ||
				!object.Name().At(i+2).IsSegment() ||
				object.Name().At(i+2).NumberVal() != 0 {
				found = false
				break
			}

			prefix = object.Name().Prefix(i)
			version = object.Name().At(i + 1).NumberVal()
			found = true
			break
		}
	}

	if !found {
		log.Warn(dv, "Prefix Announcement Object name not in correct format", "name", object.Name())
		return resError
	}

	// Check if we've seen a newer version of this prefix insertion
	prefixHash := prefix.Hash()
	if lastVersion, exists := dv.seenPrefixVersions[prefixHash]; exists && lastVersion >= version {
		log.Info(dv, "Rejecting older or duplicate prefix insertion",
			"prefix", prefix,
			"version", version,
			"lastVersion", lastVersion)
		return &mgmt.ControlResponse{
			Val: &mgmt.ControlResponseVal{
				StatusCode: 409,
				StatusText: "Older or duplicate prefix insertion version",
				Params:     nil,
			},
		}
	}

	dv.seenPrefixVersions[prefixHash] = version

	piWire := object.Content()
	params, err := tlv.ParsePrefixInsertionInnerContent(enc.NewWireView(piWire), true)
	if err != nil {
		log.Warn(dv, "Failed to parse prefix announcement object", "err", err)
		return resError
	}

	// Check validity period if it exists
	expirationPeriod := params.ExpirationPeriod
	if params.ValidityPeriod != nil {
		notBefore, err := time.Parse(spec.TimeFmt, params.ValidityPeriod.NotBefore)
		if err != nil {
			log.Warn(dv, "Failed to parse NotBefore time", "err", err, "value", params.ValidityPeriod.NotBefore)
			return resError
		}
		notAfter, err := time.Parse(spec.TimeFmt, params.ValidityPeriod.NotAfter)
		if err != nil {
			log.Warn(dv, "Failed to parse NotAfter time", "err", err, "value", params.ValidityPeriod.NotAfter)
			return resError
		}

		now := time.Now().UTC()
		if now.Before(notBefore) || now.After(notAfter) {
			log.Info(dv, "Prefix insertion outside validity period",
				"prefix", prefix,
				"notBefore", notBefore,
				"notAfter", notAfter,
				"now", now)
			return &mgmt.ControlResponse{
				Val: &mgmt.ControlResponseVal{
					StatusCode: 403,
					StatusText: "Prefix insertion outside validity period",
					Params:     nil,
				},
			}
		}

		// Adjust expiration to be the minimum of the current expiration and notAfter - now
		if expirationPeriod > 0 {
			timeUntilExpiry := notAfter.Sub(now)
			if timeUntilExpiry < time.Duration(expirationPeriod)*time.Millisecond {
				expirationPeriod = uint64(timeUntilExpiry.Milliseconds())
				log.Debug(dv, "Adjusted expiration period based on validity period",
					"prefix", prefix,
					"newExpiration", expirationPeriod)
			}
		}
	}

	var shouldRemove bool
	var cost uint64
	if expirationPeriod == 0 {
		// Remove the RIB entry
		shouldRemove = true
		cost = config.CostInfinity
	} else {
		// Add or update RIB entry
		shouldRemove = false
		cost = params.Cost.GetOr(0)
		if cost > config.CostInfinity {
			log.Warn(dv, "Invalid Cost value", "Cost", cost)
			return resError
		}
	}

	// TODO: use the expiration period to set the lifetime of the RIB and prefix table entry
	// (Currently the prefix table does not have a lifetime)

	if shouldRemove {
		dv.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "unregister",
			Args: &mgmt.ControlArgs{
				Name:   prefix,
				FaceId: optional.Some(faceId),
			},
			Retries: 3,
		})
	} else {
		dv.nfdc.Exec(nfdc.NfdMgmtCmd{
			Module: "rib",
			Cmd:    "register",
			Args: &mgmt.ControlArgs{
				Name:   prefix,
				FaceId: optional.Some(faceId),
				Origin: optional.Some(config.PrefixInsOrigin),
				Cost:   optional.Some(cost),
			},
			Retries: 3,
		})
	}

	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	if shouldRemove {
		dv.pfx.Withdraw(prefix, faceId)
	} else {
		dv.pfx.Announce(prefix, faceId, cost)
	}

	return &mgmt.ControlResponse{
		Val: &mgmt.ControlResponseVal{
			StatusCode: 200,
			StatusText: "Prefix Insertion command successful",
			Params: &mgmt.ControlArgs{
				Name:   prefix,
				FaceId: optional.Some(faceId),
				Origin: optional.Some(config.PrefixInsOrigin),
				Cost:   optional.Some(cost),
			},
		},
	}
}
