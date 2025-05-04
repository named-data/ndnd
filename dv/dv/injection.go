package dv

import (
	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/nfdc"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"time"
)

func (dv *Router) onInjection(args ndn.InterestHandlerArgs) {
	res := &mgmt.ControlResponse{
		Val: &mgmt.ControlResponseVal{
			StatusCode: 400,
			StatusText: "Failed to execute prefix injection",
			Params:     nil,
		},
	}

	reply := func() {
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
			log.Warn(dv, "Failed to make inject response Data", "err", err)
			return
		}
		args.Reply(data.Wire)
	}

	// If there is no incoming face ID, we can't use this
	if !args.IncomingFaceId.IsSet() {
		log.Warn(dv, "Received Prefix Injection with no incoming face ID, ignoring")
		reply()
		return
	}

	// Check if app param is present
	if args.Interest.AppParam() == nil {
		log.Warn(dv, "Received Prefix Injection with no AppParam, ignoring")
		reply()
		return
	}

	// Decode Prefix Injection Object
	// note: ReadData() will skip over any non-critical TLV arguments (StapledCertificate)
	data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(args.Interest.AppParam()))
	if err != nil {
		log.Warn(dv, "Failed to parse Prefix Injection AppParam", "err", err)
		reply()
		return
	}

	paParams, err := mgmt.ParsePrefixInjection(enc.NewWireView(args.Interest.AppParam()), true)
	if err != nil {
		log.Warn(dv, "Failed to parse Prefix Injection AppParam", "err", err)
		reply()
		return
	}

	var stapledCertCallbacks []ndn.ExpressCallbackArgs
	for _, certWire := range paParams.StapledCertificates {
		data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(certWire))
		if err != nil {
			log.Warn(dv, "Stapled malformed certificate", "err", err)
			reply()
			return
		}

		stapledCertCallbacks = append(stapledCertCallbacks,
			ndn.ExpressCallbackArgs{
				Result:     ndn.InterestResultData,
				Data:       data,
				RawData:    certWire,
				SigCovered: sigCov,
				IsLocal:    true,
			})
	}

	// Validate signature
	dv.prefixInjectionClient.ValidateExt(ndn.ValidateExtArgs{
		Data:       data,
		SigCovered: sigCov,
		Fetch: optional.Some(func(name enc.Name, config *ndn.InterestConfig, callback ndn.ExpressCallbackFunc) {
			for _, certCallback := range stapledCertCallbacks {
				if certCallback.Data.Name().Equal(name) {
					dv.prefixInjectionClient.Engine().Post(func() {
						callback(certCallback)
					})
					return
				}
			}

			config.NextHopId = optional.None[uint64]()
			dv.prefixInjectionClient.ExpressR(ndn.ExpressRArgs{
				Name:     name,
				Config:   config,
				Retries:  3,
				Callback: callback,
				TryStore: dv.prefixInjectionClient.Store(),
			})
		}),
		Callback: func(valid bool, err error) {
			if !valid || err != nil {
				log.Warn(dv, "Failed to validate signature", "name", data.Name(), "valid", valid, "err", err)
				reply()
				return
			}

			dv.onPrefixInjectionObject(data, args.IncomingFaceId.Unwrap(), res)
			reply()
		},
	})
}

func (dv *Router) onPrefixInjectionObject(object ndn.Data, faceId uint64, res *mgmt.ControlResponse) {
	if contentType, set := object.ContentType().Get(); !set || contentType != ndn.ContentTypePrefixInjection {
		log.Warn(dv, "Prefix Injection Object does not have the correct content type",
			"contentType", object.ContentType())
		return
	}

	// TODO: reject already seen injections (using version)
	var prefix enc.Name
	found := false

	for i, c := range object.Name() {
		if c.IsKeyword("inject") {
			prefix = object.Name().Prefix(i)
			found = true
			break
		}
	}

	if !found {
		log.Warn(dv, "Prefix Injection Object name not in correct format", "name", object.Name())
		return
	}

	piWire := object.Content()
	params, err := mgmt.ParsePrefixInjectionInnerContent(enc.NewWireView(piWire), true)
	if err != nil {
		log.Warn(dv, "Failed to parse prefix injection object", "err", err)
		return
	}

	var shouldRemove bool
	var cost uint64
	if params.ExpirationPeriod < 0 {
		log.Warn(dv, "Invalid ExpirationPeriod value", "ExpirationPeriod", params.ExpirationPeriod)
		return
	} else if params.ExpirationPeriod == 0 {
		// Remove the RIB entry
		shouldRemove = true
		cost = config.CostInfinity
	} else {
		// Add or update RIB entry
		shouldRemove = false
		cost = params.Cost.GetOr(0)
		if cost < 0 {
			log.Warn(dv, "Invalid Cost value", "Cost", cost)
			return
		}
	}

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
				Origin: optional.Some(config.PrefixInjOrigin),
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

	res.Val.StatusCode = 200
	res.Val.StatusText = "Prefix Injection command successful"
	res.Val.Params = &mgmt.ControlArgs{
		Name:   prefix,
		FaceId: optional.Some(faceId),
		Origin: optional.Some(config.PrefixInjOrigin),
		Cost:   optional.Some(cost),
	}
}
