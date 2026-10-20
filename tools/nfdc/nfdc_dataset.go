package nfdc

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/types/optional"
)

// (AI GENERATED DESCRIPTION): Fetches and returns the raw wire representation of a Data packet identified by the supplied suffix, using a consume‑only client to retrieve the content or report an error.
func (t *Tool) fetchStatusDataset(suffix enc.Name) (enc.Wire, error) {
	// consume-only client, no need for a store
	client := object.NewClient(t.engine, nil, nil)
	client.Start()
	defer client.Stop()

	ch := make(chan ndn.ConsumeState)
	client.ConsumeExt(ndn.ConsumeExtArgs{
		Name:       t.Prefix().Append(suffix...),
		NoMetadata: true, // NFD has no RDR metadata
		Callback:   func(status ndn.ConsumeState) { ch <- status },
	})

	state := <-ch
	if err := state.Error(); err != nil {
		return nil, err
	}

	return state.Content(), nil
}

func (t *Tool) fetchDataPacket(name enc.Name) (ndn.Data, error) {
	interest, err := t.engine.Spec().MakeInterest(name, &ndn.InterestConfig{
		MustBeFresh: true,
		Lifetime:    optional.Some(time.Second),
	}, nil, nil)
	if err != nil {
		return nil, err
	}

	resultCh := make(chan ndn.ExpressCallbackArgs, 1)
	if err := t.engine.Express(interest, func(args ndn.ExpressCallbackArgs) {
		resultCh <- args
	}); err != nil {
		return nil, err
	}

	result := <-resultCh
	if result.Result != ndn.InterestResultData {
		if result.Error != nil {
			return nil, result.Error
		}
		return nil, fmt.Errorf("Interest completed with result %s", result.Result)
	}
	return result.Data, nil
}
