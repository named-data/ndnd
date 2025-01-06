package nfdc

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/object"
)

func (n *Nfdc) fetchStatusDataset(suffix enc.Name) ([]byte, error) {
	// consume-only client, no need for a store
	client := object.NewClient(n.engine, nil)
	client.Start()
	defer client.Stop()

	ch := make(chan *object.ConsumeState)
	client.ConsumeExt(object.ConsumeExtArgs{
		Name:       n.GetPrefix().Append(suffix...),
		NoMetadata: true, // NFD has no RDR metadata
		Callback: func(status *object.ConsumeState) bool {
			if !status.IsComplete() {
				return true
			}
			ch <- status
			close(ch)
			return true
		},
	})

	res := <-ch
	if err := res.Error(); err != nil {
		return nil, err
	}

	return res.Content(), nil
}
