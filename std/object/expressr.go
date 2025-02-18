package object

import (
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/utils"
)

// Express a single interest with reliability
func (c *Client) ExpressR(args ndn.ExpressRArgs) {
	ExpressR(c.engine, args)
}

// Express a single interest with reliability
func ExpressR(engine ndn.Engine, args ndn.ExpressRArgs) {
	sendErr := func(err error) {
		args.Callback(ndn.ExpressCallbackArgs{
			Result: ndn.InterestResultError,
			Error:  err,
		})
	}

	// new nonce for each call
	args.Config.Nonce = utils.ConvertNonce(engine.Timer().Nonce())

	// create interest packet
	interest, err := engine.Spec().MakeInterest(args.Name, args.Config, args.AppParam, args.Signer)
	if err != nil {
		sendErr(err)
		return
	}

	// send the interest
	// TODO: reexpress faster than lifetime
	err = engine.Express(interest, func(res ndn.ExpressCallbackArgs) {
		if res.Result == ndn.InterestResultTimeout {
			log.Debug(nil, "ExpressR Interest timeout", "name", args.Name)

			// check if retries are exhausted
			if args.Retries == 0 {
				args.Callback(res)
				return
			}

			// retry on timeout
			args.Retries--
			if args.RetryCallback != nil {
				args.RetryCallback(res)
			}

			ExpressR(engine, args)
		} else {
			// all other results / errors are final
			args.Callback(res)
			return
		}
	})
	if err != nil {
		sendErr(err)
		return
	}
}
