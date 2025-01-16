package dv

import (
	"time"

	"github.com/named-data/ndnd/dv/tlv"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
)

// Received advertisement Interest
func (dv *Router) statusOnInterest(args ndn.InterestHandlerArgs) {
	status := tlv.Status{
		NetworkName: &tlv.Destination{Name: dv.config.NetworkName()},
		RouterName:  &tlv.Destination{Name: dv.config.RouterName()},
	}

	name := args.Interest.Name()
	cfg := &ndn.DataConfig{
		ContentType: utils.IdPtr(ndn.ContentTypeBlob),
		Freshness:   utils.IdPtr(time.Second),
	}
	signer := security.NewSha256Signer()

	data, err := dv.engine.Spec().MakeData(name, cfg, status.Encode(), signer)
	if err != nil {
		log.Warn(dv, "Failed to make readvertise response Data", "err", err)
		return
	}

	args.Reply(data.Wire)
}
