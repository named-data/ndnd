package nfdc

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

func (t *Tool) fetchStatusDataset(suffix enc.Name) (enc.Wire, error) {
	// NFD management datasets have no RDR metadata.
	return t.fetchObjectDataset(t.Prefix().Append(suffix...), true)
}

func (t *Tool) fetchDataPacket(name enc.Name) (ndn.Data, error) {
	interest, err := t.engine.Spec().MakeInterest(name, &ndn.InterestConfig{
		MustBeFresh: true,
		Lifetime:    optional.Some(time.Second),
		Nonce:       utils.ConvertNonce(t.engine.Timer().Nonce()),
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

func (t *Tool) fetchObjectDataset(name enc.Name, noMetadata bool) (enc.Wire, error) {
	// This client only consumes; it does not need to attach a producer handler.
	client := object.NewClient(t.engine, nil, nil)
	ch := make(chan ndn.ConsumeState, 1)
	client.ConsumeExt(ndn.ConsumeExtArgs{
		Name: name, NoMetadata: noMetadata,
		Callback: func(state ndn.ConsumeState) { ch <- state },
	})
	state := <-ch
	if err := state.Error(); err != nil {
		return nil, err
	}
	return state.Content(), nil
}
