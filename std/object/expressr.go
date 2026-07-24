package object

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/utils"
)

// Express a single interest with reliability
func (c *Client) ExpressR(args ndn.ExpressRArgs) {
	ExpressR(c.engine, args)
}

// Express a single interest with reliability
func ExpressR(engine ndn.Engine, args ndn.ExpressRArgs) {
	finalizeError := func(err error) {
		args.Callback(ndn.ExpressCallbackArgs{
			Result: ndn.InterestResultError,
			Error:  err,
		})
	}

	// Try local store if available
	if args.TryStore != nil {
		bytes, err := args.TryStore.Get(args.Name, args.Config.CanBePrefix)
		if bytes != nil && err == nil {
			wire := enc.Wire{bytes}
			data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(wire))
			if err == nil {
				// Callback should always be called on the engine goroutine
				engine.Post(func() {
					args.Callback(ndn.ExpressCallbackArgs{
						Result:     ndn.InterestResultData,
						Data:       data,
						RawData:    wire,
						SigCovered: sigCov,
						IsLocal:    true,
					})
				})
				return
			}
		}

		// Try the store only once
		args.TryStore = nil
	}

	// New nonce for each transmitted interest
	args.Config.Nonce = utils.ConvertNonce(engine.Timer().Nonce())

	// Create interest packet
	interest, err := engine.Spec().MakeInterest(args.Name, args.Config, args.AppParam, args.Signer)
	if err != nil {
		finalizeError(err)
		return
	}

	// Send the interest
	// TODO: reexpress faster than lifetime
	err = engine.Express(interest, func(res ndn.ExpressCallbackArgs) {
		// Retryable transient results: timeout and the Nacks that signal
		// "try again later" (no FIB entry yet, or downstream congestion).
		// Routing convergence in a large network can outlast a single
		// Interest lifetime, especially when DV/NLSR startup produces a
		// burst of prefix resets; without retry the first Interest after a
		// scenario transition races ahead of route propagation and the
		// caller observes an immediate failure.
		retryable := false
		switch res.Result {
		case ndn.InterestResultTimeout:
			log.Debug(nil, "ExpressR Interest timeout", "name", args.Name)
			retryable = true
		case ndn.InterestResultNack:
			switch res.NackReason {
			case spec.NackReasonNoRoute, spec.NackReasonCongestion:
				log.Debug(nil, "ExpressR retryable Nack", "name", args.Name, "reason", res.NackReason)
				retryable = true
			}
		}
		if !retryable {
			args.Callback(res)
			return
		}

		if args.Retries == 0 {
			args.Callback(res)
			return
		}
		args.Retries--
		ExpressR(engine, args)
	})
	if err != nil {
		finalizeError(err)
		return
	}
}
