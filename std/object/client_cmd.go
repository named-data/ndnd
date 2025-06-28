package object

import (
	"fmt"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

// This whole module will change from the current ugly design.

func (c *Client) AttachCommandHandler(
	handlerName enc.Name,
	handler func(enc.Name, enc.Wire, func(enc.Wire) error),
) error {
	return c.engine.AttachHandler(handlerName, func(args ndn.InterestHandlerArgs) {
		param := args.Interest.AppParam()
		if len(param) == 0 {
			log.Debug(c, "Command received without application parameters")
			return
		}

		data, sigCov, err := spec.Spec{}.ReadData(enc.NewWireView(param))
		if err != nil {
			log.Debug(c, "Failed to parse command data", "err", err)
			return
		}

		c.Validate(data, sigCov, func(valid bool, err error) {
			if !valid {
				log.Debug(c, "Command data validation failed", "err", err)
				return
			}

			cmdName := data.Name()
			handler(cmdName, data.Content(), func(wire enc.Wire) error {
				resName := args.Interest.Name()

				signer := c.SuggestSigner(resName)
				if signer == nil {
					err = fmt.Errorf("no signer found for command: %s", resName)
					log.Error(c, err.Error())
					return err
				}

				dataCfg := ndn.DataConfig{}
				resData, err := spec.Spec{}.MakeData(resName, &dataCfg, wire, signer)
				if err != nil {
					err = fmt.Errorf("failed to make command response data: %w", err)
					log.Error(c, err.Error())
					return err
				}

				return args.Reply(resData.Wire)
			})
		})
	})
}

func (c *Client) DetachCommandHandler(name enc.Name) error {
	return c.engine.DetachHandler(name)
}

func (c *Client) ExpressCommand(dest enc.Name, name enc.Name, cmd enc.Wire, callback func(enc.Wire, error)) {
	signer := c.SuggestSigner(name)
	if signer == nil {
		callback(nil, fmt.Errorf("no signer found for command: %s", name))
		return
	}

	dataCfg := ndn.DataConfig{}
	data, err := spec.Spec{}.MakeData(name, &dataCfg, cmd, signer)
	if err != nil {
		callback(nil, fmt.Errorf("failed to make command data: %w", err))
		return
	}

	c.ExpressR(ndn.ExpressRArgs{
		Name: dest,
		Config: &ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		AppParam: data.Wire,
		Retries:  0,
		Callback: func(args ndn.ExpressCallbackArgs) {
			if args.Result != ndn.InterestResultData {
				callback(nil, fmt.Errorf("command failed: %s", args.Result))
				return
			}
			c.Validate(args.Data, data.Wire, func(valid bool, err error) {
				if !valid {
					callback(nil, fmt.Errorf("command data validation failed: %w", err))
					return
				}
				callback(args.Data.Content(), nil)
			})
		},
	})
}
