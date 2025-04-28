package object

import (
	"fmt"
	"runtime"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

// size of produced segment (~800B for header)
const pSegmentSize = 8000

// Produce and sign data, and insert into a store
// This function does not rely on the engine or client, so it can also be used in YaNFD
func Produce(args ndn.ProduceArgs, store ndn.Store, signer ndn.Signer) (enc.Name, error) {
	content := args.Content
	contentSize := content.Length()

	// Get the correct version
	if !args.Name.At(-1).IsVersion() {
		return nil, fmt.Errorf("object version not set: %s", args.Name)
	}
	version := args.Name.At(-1).NumberVal()

	// Use freshness period or default
	if args.FreshnessPeriod == 0 {
		args.FreshnessPeriod = 4 * time.Second
	}

	// Compute final block ID with segment count
	lastSeg := uint64(0)
	if contentSize > 0 {
		lastSeg = uint64((contentSize - 1) / pSegmentSize)
	}

	cfg := &ndn.DataConfig{
		ContentType:  optional.Some(ndn.ContentTypeBlob),
		Freshness:    optional.Some(args.FreshnessPeriod),
		FinalBlockID: optional.Some(enc.NewSegmentComponent(lastSeg)),
	}

	// use a transaction to ensure the entire object is written
	tx, err := store.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Commit()

	var seg uint64
	for seg = 0; seg <= lastSeg; seg++ {
		name := args.Name.Append(enc.NewSegmentComponent(seg))

		segContent := enc.Wire{}
		segContentSize := 0
		for len(content) > 0 && segContentSize < pSegmentSize {
			// append wire from content to segContent till segment is full
			sizeLeft := min(pSegmentSize-segContentSize, len(content[0]))
			newContent := content[0][:sizeLeft]
			segContent = append(segContent, newContent)
			segContentSize += len(newContent)

			// remove the content from the content slice
			content[0] = content[0][sizeLeft:]
			if len(content[0]) == 0 {
				content[0] = nil // gc
				content = content[1:]
			}
		}

		data, err := spec.Spec{}.MakeData(name, cfg, segContent, signer)
		if err != nil {
			return nil, err
		}

		err = tx.Put(name, data.Wire.Join())
		if err != nil {
			return nil, err
		}

		// force run GC every ~80MB to prevent excessive memory usage
		if seg > 0 && seg%10000 == 0 {
			runtime.GC() // slow
		}
	}

	if !args.NoMetadata {
		// write metadata packet
		name := args.Name.Prefix(-1).
			Append(enc.NewKeywordComponent(rdr.MetadataKeyword)).
			Append(enc.NewVersionComponent(version)).
			Append(enc.NewSegmentComponent(0))
		content := rdr.MetaData{
			Name:         args.Name,
			FinalBlockID: cfg.FinalBlockID.Unwrap().Bytes(),
		}

		data, err := spec.Spec{}.MakeData(name, cfg, content.Encode(), signer)
		if err != nil {
			return nil, err
		}

		err = tx.Put(name, data.Wire.Join())
		if err != nil {
			return nil, err
		}
	}

	return args.Name, nil
}

// Produce and sign data, and insert into the client's store.
// The input data will be freed as the object is segmented.
func (c *Client) Produce(args ndn.ProduceArgs) (enc.Name, error) {
	if !args.Name.At(-1).IsVersion() {
		return nil, fmt.Errorf("object version not set: %s", args.Name)
	}

	signer := c.SuggestSigner(args.Name.Prefix(-1))
	if signer == nil {
		return nil, fmt.Errorf("no valid signer found for %s", args.Name)
	}

	return Produce(args, c.store, signer)
}

// Remove an object from the client's store by name
func (c *Client) Remove(name enc.Name) error {
	// This will clear the store (probably not what you want)
	if len(name) == 0 {
		return nil
	}

	tx, err := c.store.Begin()
	if err != nil {
		return err
	}
	defer tx.Commit()

	// Remove object data
	err = tx.RemovePrefix(name)
	if err != nil {
		return err
	}

	// Remove RDR metadata if we have a version
	// If there is no version, we removed this anyway in the previous step
	if version := name.At(-1); version.IsVersion() {
		metadata := name.Prefix(-1).Append(enc.NewKeywordComponent(rdr.MetadataKeyword), version)
		err = tx.RemovePrefix(metadata)
		if err != nil {
			return err
		}
	}

	return nil
}

// onInterest looks up the store for the requested data
func (c *Client) onInterest(args ndn.InterestHandlerArgs) {
	// TODO: consult security if we can send this
	wire, err := c.store.Get(args.Interest.Name(), args.Interest.CanBePrefix())
	if err != nil || wire == nil {
		return
	}
	args.Reply(enc.Wire{wire})
}
