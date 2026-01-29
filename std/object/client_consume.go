package object

import (
	"fmt"
	"sync/atomic"
	"time"

	"slices"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

// maximum number of segments in an object (for safety)
const maxObjectSeg = 1e8

// Consume an object with a given name
func (c *Client) Consume(name enc.Name, callback func(status ndn.ConsumeState)) {
	c.ConsumeExt(ndn.ConsumeExtArgs{Name: name, Callback: callback})
}

// ConsumeExt is a more advanced consume API that allows for more control
// over the fetching process.
func (c *Client) ConsumeExt(args ndn.ConsumeExtArgs) {
	// clone the name for good measure
	args.Name = args.Name.Clone()

	// create new consume state
	c.consumeObject(&ConsumeState{
		args:      args,
		err:       nil,
		content:   make(enc.Wire, 0), // just in case
		complete:  atomic.Bool{},
		meta:      nil,
		fetchName: args.Name,
		wnd:       FetchWindow{},
		segCnt:    -1,
	})
}

// (AI GENERATED DESCRIPTION): Consumes an object by first fetching (or extracting) its metadata when the name lacks a version component, then retrieving its data segments, or directly fetching the segments if the name already contains a version.
func (c *Client) consumeObject(state *ConsumeState) {
	name := state.fetchName

	// will segfault if name is empty
	if len(name) == 0 {
		state.finalizeError(fmt.Errorf("%w: consume name cannot be empty", ndn.ErrProtocol))
		return
	}

	// fetch object metadata if the last name component is not a version
	if !name.At(-1).IsVersion() {
		// when called with metadata, call with versioned name.
		// state will always have the original object name.
		if state.meta != nil {
			state.finalizeError(fmt.Errorf("%w: metadata does not have version component", ndn.ErrProtocol))
			return
		}

		// if metadata fetching is disabled, just attempt to fetch one segment
		// with the prefix, then get the versioned name from the segment.
		if state.args.NoMetadata {
			c.fetchDataByPrefix(name, state.args.TryStore, state.args.IgnoreValidity.GetOr(false),
				func(data ndn.Data, err error) {
					if err != nil {
						state.finalizeError(err)
						return
					}
					meta, err := extractSegMetadata(data)
					if err != nil {
						state.finalizeError(err)
						return
					}
					c.consumeObjectWithMeta(state, meta)
				})
			return
		}

		// fetch RDR metadata for this object
		c.fetchMetadata(name, state.args.TryStore, state.args.IgnoreValidity.GetOr(false),
			func(meta *rdr.MetaData, err error) {
				if err != nil {
					state.finalizeError(err)
					return
				}
				c.consumeObjectWithMeta(state, meta)
			})
		return
	}

	// passes ownership of state and callback to fetcher
	c.fetcher.add(state)
}

// consumeObjectWithMeta consumes an object with a given metadata
func (c *Client) consumeObjectWithMeta(state *ConsumeState, meta *rdr.MetaData) {
	state.meta = meta
	state.fetchName = meta.Name
	c.consumeObject(state)
}

// fetchMetadata gets the RDR metadata for an object with a given name
func (c *Client) fetchMetadata(
	name enc.Name,
	tryStore bool,
	ignoreValidity bool,
	callback func(meta *rdr.MetaData, err error),
) {
	log.Debug(c, "Fetching object metadata", "name", name)
	c.ExpressR(ndn.ExpressRArgs{
		Name: name.Append(enc.NewKeywordComponent(rdr.MetadataKeyword)),
		Config: &ndn.InterestConfig{
			CanBePrefix: true,
			MustBeFresh: true,
			Lifetime:    optional.Some(time.Millisecond * 1000),
		},
		Retries:  3, // TODO: configurable
		TryStore: utils.If(tryStore, c.store, nil),
		Callback: func(args ndn.ExpressCallbackArgs) {
			if args.Result == ndn.InterestResultError {
				callback(nil, fmt.Errorf("%w: fetch metadata failed: %w", ndn.ErrNetwork, args.Error))
				return
			}

			if args.Result != ndn.InterestResultData {
				callback(nil, fmt.Errorf("%w: fetch metadata failed with result: %s", ndn.ErrNetwork, args.Result))
				return
			}
			c.ValidateExt(ndn.ValidateExtArgs{
				Data:           args.Data,
				SigCovered:     args.SigCovered,
				IgnoreValidity: optional.Some(ignoreValidity),
				Callback: func(valid bool, err error) {
					// validate with trust config
					if !valid {
						callback(nil, fmt.Errorf("%w: validate metadata failed: %w", ndn.ErrSecurity, err))
						return
					}

					// parse metadata
					metadata, err := rdr.ParseMetaData(enc.NewWireView(args.Data.Content()), false)
					if err != nil {
						callback(nil, fmt.Errorf("%w: failed to parse object metadata: %w", ndn.ErrProtocol, err))
						return
					}

					// clone fields for lifetime
					metadata.Name = metadata.Name.Clone()
					metadata.FinalBlockID = slices.Clone(metadata.FinalBlockID)
					callback(metadata, nil)
				},
			})
		},
	})
}

// fetchWithPrefix gets any fresh data with a given prefix
func (c *Client) fetchDataByPrefix(
	name enc.Name,
	tryStore bool,
	ignoreValidity bool,
	callback func(data ndn.Data, err error),
) {
	log.Debug(c, "Fetching data with prefix", "name", name)
	c.ExpressR(ndn.ExpressRArgs{
		Name: name,
		Config: &ndn.InterestConfig{
			CanBePrefix: true,
			MustBeFresh: true,
			Lifetime:    optional.Some(time.Millisecond * 1000),
		},
		Retries:  3, // TODO: configurable
		TryStore: utils.If(tryStore, c.store, nil),
		Callback: func(args ndn.ExpressCallbackArgs) {
			if args.Result == ndn.InterestResultError {
				callback(nil, fmt.Errorf("%w: fetch by prefix failed: %w", ndn.ErrNetwork, args.Error))
				return
			}

			if args.Result != ndn.InterestResultData {
				callback(nil, fmt.Errorf("%w: fetch by prefix failed with result: %s", ndn.ErrNetwork, args.Result))
				return
			}
			c.ValidateExt(ndn.ValidateExtArgs{
				Data:           args.Data,
				SigCovered:     args.SigCovered,
				IgnoreValidity: optional.Some(ignoreValidity),
				Callback: func(valid bool, err error) {
					if !valid {
						callback(nil, fmt.Errorf("%w: validate by prefix failed: %w", ndn.ErrSecurity, err))
						return
					}

					callback(args.Data, nil)
				},
			})
		},
	})
}

// extractSegMetadata constructs partial metadata from a given data segment
// returns (metadata, error)
func extractSegMetadata(data ndn.Data) (*rdr.MetaData, error) {
	// check if the object has segment and version components
	name := data.Name()
	if len(name) < 2 {
		return nil, fmt.Errorf("%w: data has no version or segment", ndn.ErrProtocol)
	}

	// get segment component
	if !name.At(-1).IsSegment() {
		return nil, fmt.Errorf("%w: data has no segment", ndn.ErrProtocol)
	}

	// get version component
	if !name.At(-2).IsVersion() {
		return nil, fmt.Errorf("%w: data has no version", ndn.ErrProtocol)
	}

	// construct metadata
	return &rdr.MetaData{Name: name.Prefix(-1)}, nil
}
