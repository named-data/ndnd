package dv

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
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
	data, _ /*sigCov*/, err := spec.Spec{}.ReadData(enc.NewWireView(args.Interest.AppParam()))
	if err != nil {
		log.Warn(dv, "Failed to parse Prefix Injection AppParam", "err", err)
		return
	}

	// TODO: perform signature validation
	if true {
		// validation would be here
		/*
			if !valid || err != nil {
				log.Warn(dv, "Failed to validate signature", "name", data.Name(), "valid", valid, "err", err)
				return
			}
		*/

		dv.onPrefixInjectionObject(data, args.IncomingFaceId.Unwrap())
	}
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

	// TODO: parse content, get cost
	cost := uint64(0)
	dirty := dv.rib.Set(prefix, dv.config.RouterName(), cost)

	if dirty {
		go dv.postUpdateRib()
	}
}
