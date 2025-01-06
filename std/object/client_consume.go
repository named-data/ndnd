package object

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
	"github.com/named-data/ndnd/std/utils"
)

// maximum number of segments in an object (for safety)
const maxObjectSeg = 1e8

// callback for consume API
// return true to continue fetching the object
type ConsumeCallback func(status *ConsumeState) bool

// arguments for the consume callback
type ConsumeState struct {
	// original arguments
	args ConsumeExtArgs
	// error that occurred during fetching
	err error
	// raw data contents.
	content enc.Wire
	// fetching is completed
	complete bool
	// fetched metadata
	meta *rdr.MetaData
	// versioned object name
	fetchName enc.Name

	// fetching window
	// - [0] is the position till which the user has already consumed the fetched buffer
	// - [1] is the position till which the buffer is valid (window start)
	// - [2] is the end of the current fetching window
	//
	// content[0:wnd[0]] is invalid (already used and freed)
	// content[wnd[0]:wnd[1]] is valid (not used yet)
	// content[wnd[1]:wnd[2]] is currently being fetched
	// content[wnd[2]:] will be fetched in the future
	wnd [3]int

	// segment count from final block id (-1 if unknown)
	segCnt int
}

// returns the name of the object being consumed
func (a *ConsumeState) Name() enc.Name {
	return a.fetchName
}

// returns the error that occurred during fetching
func (a *ConsumeState) Error() error {
	return a.err
}

// returns true if the content has been completely fetched
func (a *ConsumeState) IsComplete() bool {
	return a.complete
}

// returns the currently available buffer in the content
// any subsequent calls to Content() will return data after the previous call
func (a *ConsumeState) Content() []byte {
	// return valid range of buffer (can be empty)
	buf := a.content[a.wnd[0]:a.wnd[1]].Join()

	// free buffers
	for i := a.wnd[0]; i < a.wnd[1]; i++ {
		a.content[i] = nil // gc
	}

	a.wnd[0] = a.wnd[1]
	return buf
}

// get the progress counter
func (a *ConsumeState) Progress() int {
	return a.wnd[1]
}

// get the max value for the progress counter (-1 for unknown)
func (a *ConsumeState) ProgressMax() int {
	return a.segCnt
}

// send a fatal error to the callback
func (a *ConsumeState) finalizeError(err error) {
	if !a.complete {
		a.err = err
		a.complete = true
		a.args.Callback(a)
	}
}

// Consume an object with a given name
func (c *Client) Consume(name enc.Name, callback ConsumeCallback) {
	c.ConsumeExt(ConsumeExtArgs{Name: name, Callback: callback})
}

// ConsumeExtArgs are arguments for the ConsumeExt API
type ConsumeExtArgs struct {
	// name of the object to consume
	Name enc.Name
	// callback when data is available
	Callback ConsumeCallback
	// do not fetch metadata packet (advanced usage)
	NoMetadata bool
}

// ConsumeExt is a more advanced consume API that allows for more control
// over the fetching process.
func (c *Client) ConsumeExt(args ConsumeExtArgs) {
	// clone the name for good measure
	args.Name = args.Name.Clone()

	// create new consume state
	c.consumeObject(&ConsumeState{
		args:      args,
		err:       nil,
		content:   make(enc.Wire, 0), // just in case
		complete:  false,
		meta:      nil,
		fetchName: args.Name,
		wnd:       [3]int{0, 0},
		segCnt:    -1,
	})
}

func (c *Client) consumeObject(state *ConsumeState) {
	name := state.fetchName

	// will segfault if name is empty
	if len(name) == 0 {
		state.finalizeError(fmt.Errorf("consume: name cannot be empty"))
		return
	}

	// fetch object metadata if the last name component is not a version
	if name[len(name)-1].Typ != enc.TypeVersionNameComponent {
		// when called with metadata, call with versioned name.
		// state will always have the original object name.
		if state.meta != nil {
			state.finalizeError(fmt.Errorf("consume: metadata does not have version component"))
			return
		}

		// if metadata fetching is disabled, just attempt to fetch one segment
		// with the prefix, then get the versioned name from the segment.
		if state.args.NoMetadata {
			c.fetchDataByPrefix(name, func(data ndn.Data, err error) {
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
		}

		// fetch RDR metadata for this object
		c.fetchMetadata(name, func(meta *rdr.MetaData, err error) {
			if err != nil {
				state.finalizeError(err)
				return
			}
			c.consumeObjectWithMeta(state, meta)
		})
		return
	}

	// passes ownership of state and callback to fetcher
	c.segfetch <- state
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
	callback func(meta *rdr.MetaData, err error),
) {
	log.Debugf("consume: fetching object metadata %s", name)
	args := ExpressRArgs{
		Name: name.Append(rdr.METADATA),
		Config: &ndn.InterestConfig{
			CanBePrefix: true,
			MustBeFresh: true,
			Lifetime:    utils.IdPtr(time.Millisecond * 1000),
		},
		Retries: 3,
	}
	c.ExpressR(args, func(args ndn.ExpressCallbackArgs) {
		if args.Result == ndn.InterestResultError {
			callback(nil, fmt.Errorf("consume: fetch failed with error %v", args.Error))
			return
		}

		if args.Result != ndn.InterestResultData {
			callback(nil, fmt.Errorf("consume: fetch failed with result %d", args.Result))
			return
		}

		// parse metadata
		metadata, err := rdr.ParseMetaData(enc.NewWireReader(args.Data.Content()), false)
		if err != nil {
			callback(nil, fmt.Errorf("consume: failed to parse object metadata %v", err))
			return
		}

		// clone fields for lifetime
		metadata.Name = metadata.Name.Clone()
		metadata.FinalBlockID = append([]byte{}, metadata.FinalBlockID...)
		callback(metadata, nil)
	})
}

// fetchWithPrefix gets any fresh data with a given prefix
func (c *Client) fetchDataByPrefix(
	name enc.Name,
	callback func(data ndn.Data, err error),
) {
	log.Debugf("consume: fetching data with prefix %s", name)
	args := ExpressRArgs{
		Name: name,
		Config: &ndn.InterestConfig{
			CanBePrefix: true,
			MustBeFresh: true,
			Lifetime:    utils.IdPtr(time.Millisecond * 1000),
		},
		Retries: 3,
	}
	c.ExpressR(args, func(args ndn.ExpressCallbackArgs) {
		if args.Result == ndn.InterestResultError {
			callback(nil, fmt.Errorf("consume: fetch failed with error %v", args.Error))
			return
		}

		if args.Result != ndn.InterestResultData {
			callback(nil, fmt.Errorf("consume: fetch failed with result %d", args.Result))
			return
		}

		callback(args.Data, nil)
	})
}

// extractSegMetadata constructs partial metadata from a given data segment
// returns (metadata, error)
func extractSegMetadata(data ndn.Data) (*rdr.MetaData, error) {
	// check if the object has segment and version components
	name := data.Name()
	if len(name) < 2 {
		return nil, fmt.Errorf("consume: data has no version or segment")
	}

	// get segment component
	segComp := name[len(name)-1]
	if segComp.Typ != enc.TypeSegmentNameComponent {
		return nil, fmt.Errorf("consume: data has no segment")
	}

	// get version component
	verComp := name[len(name)-2]
	if verComp.Typ != enc.TypeVersionNameComponent {
		return nil, fmt.Errorf("consume: data has no version")
	}

	// construct metadata
	return &rdr.MetaData{
		Name:         name[:len(name)-1],
		FinalBlockID: segComp.Bytes(),
	}, nil
}
