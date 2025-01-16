package object

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/utils"
)

// arguments for the express retry API
type ExpressRArgs struct {
	Name     enc.Name
	Config   *ndn.InterestConfig
	AppParam enc.Wire
	Signer   ndn.Signer
	Retries  int

	callback ndn.ExpressCallbackFunc
}

// (advanced) express a single interest with reliability
func (c *Client) ExpressR(args ExpressRArgs, callback ndn.ExpressCallbackFunc) {
	args.callback = callback
	c.outpipe <- args
}

func (c *Client) expressRImpl(args ExpressRArgs) {
	sendErr := func(err error) {
		args.callback(ndn.ExpressCallbackArgs{
			Result: ndn.InterestResultError,
			Error:  err,
		})
	}

	// new nonce for each call
	args.Config.Nonce = utils.ConvertNonce(c.engine.Timer().Nonce())

	// create interest packet
	interest, err := c.engine.Spec().MakeInterest(args.Name, args.Config, args.AppParam, args.Signer)
	if err != nil {
		sendErr(err)
		return
	}

	// send the interest
	// TODO: reexpress faster than lifetime
	err = c.engine.Express(interest, func(res ndn.ExpressCallbackArgs) {
		if res.Result == ndn.InterestResultTimeout {
			log.Debug(c, "ExpressR Interest timeout", "name", args.Name)

			// check if retries are exhausted
			if args.Retries == 0 {
				args.callback(res)
				return
			}

			// retry on timeout
			args.Retries--
			c.ExpressR(args, args.callback)
		} else {
			// all other results / errors are final
			args.callback(res)
			return
		}
	})
	if err != nil {
		sendErr(err)
		return
	}
}
