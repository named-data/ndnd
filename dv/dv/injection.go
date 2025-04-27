package dv

import (
	"github.com/named-data/ndnd/dv/config"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

func (dv *Router) onInjection(args ndn.InterestHandlerArgs) {
	// If there is no incoming face ID, we can't use this
	if !args.IncomingFaceId.IsSet() {
		log.Warn(dv, "Received Prefix Injection with no incoming face ID, ignoring")
		return
	}

	// Check if app param is present
	if args.Interest.AppParam() == nil {
		log.Warn(dv, "Received Prefix Injection with no AppParam, ignoring")
		return
	}

	// Decode Prefix Injection Object
	// note: ReadData() will skip over any non-critical TLV arguments (StapledCertificate)
	data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(args.Interest.AppParam()))
	if err != nil {
		log.Warn(dv, "Failed to parse Prefix Injection AppParam", "err", err)
		return
	}

	// Validate signature
	// TODO: use stapled certificates
	dv.prefixInjectionClient.ValidateExt(ndn.ValidateExtArgs{
		Data:        data,
		SigCovered:  sigCov,
		CertNextHop: args.IncomingFaceId, /* is this sensible? */
		Callback: func(valid bool, err error) {
			if !valid || err != nil {
				log.Warn(dv, "Failed to validate signature", "name", data.Name(), "valid", valid, "err", err)
				return
			}

			// TODO: need to add into FIB? Otherwise what to do with the incoming FaceId?
			dv.onPrefixInjectionObject(data, args.IncomingFaceId.Unwrap())
		},
	})
}

func (dv *Router) onPrefixInjectionObject(object ndn.Data, faceId uint64) {
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
	params, err := mgmt.ParsePrefixInjection(enc.NewWireView(piWire), true)
	if err != nil {
		log.Warn(dv, "Failed to parse prefix injection object", "err", err)
		return
	}

	var cost uint64
	if params.ExpirationPeriod < 0 {
		log.Warn(dv, "Invalid ExpirationPeriod value", "ExpirationPeriod", params.ExpirationPeriod)
		return
	} else if params.ExpirationPeriod == 0 {
		// Remove the RIB entry
		// TODO: do it the proper way
		cost = config.CostInfinity
	} else {
		// Add or update RIB entry
		cost = params.Cost.GetOr(0)
		if cost < 0 {
			log.Warn(dv, "Invalid Cost value", "Cost", cost)
			return
		}
	}

	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	dirty := dv.rib.Set(prefix, dv.config.RouterName(), cost)
	if dirty {
		go dv.postUpdateRib()
	}
}
