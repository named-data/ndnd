package object

import (
	"errors"
	"runtime"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
)

// size of produced segment (~800B for header)
const pSegmentSize = 8000

type ProduceArgs struct {
	// name of the object to produce
	Name enc.Name
	// raw data contents
	Content enc.Wire
	// version of the object (defaults to unix timestamp, 0 for immutable)
	Version *uint64
	// time for which the object version can be cached (default 4s)
	FreshnessPeriod time.Duration
	// do not create metadata packet
	NoMetadata bool
}

// Produce and sign data, and insert into a store
// This function does not rely on the engine or client, so it can also be used in YaNFD
func Produce(args ProduceArgs, store ndn.Store, signer ndn.Signer) (enc.Name, error) {
	content := args.Content
	contentSize := content.Length()

	now := time.Now().UnixNano()
	if now < 0 { // > 1970
		return nil, errors.New("current unix time is negative")
	}

	version := uint64(now)
	if args.Version != nil {
		version = *args.Version
	}

	if args.FreshnessPeriod == 0 {
		args.FreshnessPeriod = 4 * time.Second
	}

	lastSeg := uint64(0)
	if contentSize > 0 {
		lastSeg = uint64((contentSize - 1) / pSegmentSize)
	}
	finalBlockId := enc.NewSegmentComponent(lastSeg)

	cfg := &ndn.DataConfig{
		ContentType:  utils.IdPtr(ndn.ContentTypeBlob),
		Freshness:    utils.IdPtr(args.FreshnessPeriod),
		FinalBlockID: &finalBlockId,
	}

	basename := args.Name.Append(enc.NewVersionComponent(version))

	// use a transaction to ensure the entire object is written
	store.Begin()
	defer store.Commit()

	var seg uint64
	for seg = 0; seg <= lastSeg; seg++ {
		name := basename.Append(enc.NewSegmentComponent(seg))

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

		err = store.Put(name, version, data.Wire.Join())
		if err != nil {
			return nil, err
		}

		// force run GC every ~80MB to prevent excessive memory usage
		if seg%10000 == 0 {
			runtime.GC() // slow
		}
	}

	if !args.NoMetadata {
		// write metadata packet
		name := args.Name.Append(
			rdr.METADATA,
			enc.NewVersionComponent(version),
			enc.NewSegmentComponent(0),
		)
		content := rdr.MetaData{
			Name:         basename,
			FinalBlockID: finalBlockId.Bytes(),
		}

		data, err := spec.Spec{}.MakeData(name, cfg, content.Encode(), signer)
		if err != nil {
			return nil, err
		}

		err = store.Put(name, version, data.Wire.Join())
		if err != nil {
			return nil, err
		}
	}

	return basename, nil
}

// Produce and sign data, and insert into the client's store.
// The input data will be freed as the object is segmented.
func (c *Client) Produce(args ProduceArgs) (enc.Name, error) {
	// TODO: sign the data
	signer := sec.NewSha256Signer()

	return Produce(args, c.store, signer)
}

// Remove an object from the client's store by name
func (c *Client) Remove(name enc.Name) error {
	// This will clear the store (probably not what you want)
	if len(name) == 0 {
		return nil
	}

	c.store.Begin()
	defer c.store.Commit()

	// Remove object data
	err := c.store.Remove(name, true)
	if err != nil {
		return err
	}

	// Remove RDR metadata if we have a version
	// If there is no version, we removed this anyway in the previous step
	if version := name[len(name)-1]; version.Typ == enc.TypeVersionNameComponent {
		err = c.store.Remove(name[:len(name)-1].Append(rdr.METADATA, version), true)
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
