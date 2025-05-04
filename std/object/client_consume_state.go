package object

import (
	"sync/atomic"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
)

// arguments for the consume callback
type ConsumeState struct {
	// original arguments
	args ndn.ConsumeExtArgs
	// error that occurred during fetching
	err error
	// raw data contents.
	content enc.Wire
	// fetching is completed
	complete atomic.Bool
	// fetched metadata
	meta *rdr.MetaData
	// versioned object name
	fetchName enc.Name

	// content[0:Valid] is invalid (already used and freed)
	// content[Valid:Fetching] is fetched and valid (not used yet)
	// content[Fetching:Pending] is currently being fetched
	// content[Pending:] will be fetched in the future
	wnd FetchWindow

	// segment count from final block id (-1 if unknown)
	segCnt int
}

// FetchWindow holds the state of the fetching window
// It tracks the progress of data fetching and availability
type FetchWindow struct {
	Valid    int // the position from which the data has been fetched and is valid
	Fetching int // the position from which the data is being fetched (window start)
	Pending  int // the position from which the data is pending to be fetched (end of the current fetching window)
}

// returns the name of the object being consumed
func (a *ConsumeState) Name() enc.Name {
	return a.fetchName
}

// returns the version of the object being consumed
func (a *ConsumeState) Version() uint64 {
	if ver := a.fetchName.At(-1); ver.IsVersion() {
		return ver.NumberVal()
	}
	return 0
}

// returns the error that occurred during fetching
func (a *ConsumeState) Error() error {
	return a.err
}

// returns true if the content has been completely fetched
func (a *ConsumeState) IsComplete() bool {
	return a.complete.Load()
}

// returns the currently available buffer in the content
// any subsequent calls to Content() will return data after the previous call
func (a *ConsumeState) Content() enc.Wire {
	// return valid range of buffer (can be empty)
	wire := make(enc.Wire, a.wnd.Fetching-a.wnd.Valid)

	// free buffers
	for i := a.wnd.Valid; i < a.wnd.Fetching; i++ {
		wire[i-a.wnd.Valid] = a.content[i] // retain
		a.content[i] = nil                 // gc
	}

	a.wnd.Valid = a.wnd.Fetching
	return wire
}

// get the progress counter
func (a *ConsumeState) Progress() int {
	return a.wnd.Fetching
}

// get the max value for the progress counter (-1 for unknown)
func (a *ConsumeState) ProgressMax() int {
	return a.segCnt
}

// cancel the consume operation
func (a *ConsumeState) Cancel() {
	if !a.complete.Swap(true) {
		a.err = ndn.ErrCancelled
	}
}

// send a fatal error to the callback
func (a *ConsumeState) finalizeError(err error) {
	if !a.complete.Swap(true) {
		a.err = err
		a.args.Callback(a)
	}
}
