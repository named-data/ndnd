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

	// fetching window
	// Valid is the position from which the data is available
	// Fetching is the position from which the data are currently being fetched (window start)
	// Pending is the position from which the data will be fetched in the future
	//
	// content[0:Valid] is invalid (already used and freed)
	// content[Valid:Fetching] is fetched and valid (not used yet)
	// content[Fetching:Pending] is currently being fetched
	// content[Pending:] will be fetched in the future
	wnd FetchWindow

	// segment count from final block id (-1 if unknown)
	segCnt int
}

// FetchWindow holds the state of the fetching window
type FetchWindow struct {
	Valid    atomic.Int64
	Fetching atomic.Int64
	Pending  atomic.Int64
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
	wire := make(enc.Wire, a.wnd.GetFetching()-a.wnd.GetValid())

	// free buffers
	for i := a.wnd.GetValid(); i < a.wnd.GetFetching(); i++ {
		wire[i-a.wnd.GetValid()] = a.content[i] // retain
		a.content[i] = nil                      // gc
	}

	a.wnd.SetValid(a.wnd.GetFetching())
	return wire
}

// get the progress counter
func (a *ConsumeState) Progress() int {
	return int(a.wnd.GetFetching())
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

// sets the start position in the buffer where data is valid and not yet used
func (wnd *FetchWindow) SetValid(val int) {
	wnd.Valid.Store(int64(val))
}

// sets the start position in the buffer where data is currently being fetched
func (wnd *FetchWindow) SetFetching(val int) {
	wnd.Fetching.Store(int64(val))
}

// sets the start position in the buffer where data is pending to be fetched
func (wnd *FetchWindow) SetPending(val int) {
	wnd.Pending.Store(int64(val))
}

// returns the start position in the buffer where data is valid and not yet used
func (wnd *FetchWindow) GetValid() int {
	return int(wnd.Valid.Load())
}

// returns the start position in the buffer where data is currently being fetched
func (wnd *FetchWindow) GetFetching() int {
	return int(wnd.Fetching.Load())
}

// returns the start position in the buffer where data is pending to be fetched
func (wnd *FetchWindow) GetPending() int {
	return int(wnd.Pending.Load())
}

// returns if the buffer position is already used and freed
func (wnd *FetchWindow) IsInvalid(index int) bool {
	return index < wnd.GetValid()
}

// returns if the buffer position holds valid data that is not yet used
func (wnd *FetchWindow) IsValid(index int) bool {
	return index >= wnd.GetValid() && index < wnd.GetFetching()
}

// returns if the buffer position holds data that is currently being fetched
func (wnd *FetchWindow) IsFetching(index int) bool {
	return index >= wnd.GetFetching() && index < wnd.GetPending()
}

// returns if the position holds data to be fetched
func (wnd *FetchWindow) IsPending(index int) bool {
	return index >= wnd.GetPending()
}

// advances the start position in the buffer where data is valid and not yet used by 1
func (wnd *FetchWindow) AdvanceValid() {
	wnd.Valid.Add(1)
}

// advances the start position in the buffer where data is currently being fetched by 1
func (wnd *FetchWindow) AdvanceFetching() {
	wnd.Fetching.Add(1)
}

// advances the start position in the buffer where data is pending to be fetched by 1
func (wnd *FetchWindow) AdvancePending() {
	wnd.Pending.Add(1)
}
