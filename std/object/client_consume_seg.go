package object

import (
	"fmt"
	"slices"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object/congestion"
)

// round-robin based segment fetcher
// no lock is needed because there is a single goroutine that does both
// check() and handleData() in the client class
type rrSegFetcher struct {
	// mutex for the fetcher
	mutex sync.RWMutex
	// ref to parent
	client *Client
	// list of active streams
	streams []*ConsumeState
	// round robin index
	rrIndex int
	// number of outstanding interests
	outstanding int
	// window size
	window congestion.CongestionWindow
}

func newRrSegFetcher(client *Client) rrSegFetcher {
	return rrSegFetcher{
		mutex:       sync.RWMutex{},
		client:      client,
		streams:     make([]*ConsumeState, 0),
		window:      congestion.NewFixedCongestionWindow(100),	// fixed window trial
		outstanding: 0,
	}
}

// log identifier
func (s *rrSegFetcher) String() string {
	return "client-seg"
}

// if there are too many outstanding segments
func (s *rrSegFetcher) IsCongested() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.outstanding >= s.window.Size()
}

// add a stream to the fetch queue
func (s *rrSegFetcher) add(state *ConsumeState) {
	log.Debug(s, "Adding stream to fetch queue", "name", state.fetchName)
	s.mutex.Lock()
	s.streams = append(s.streams, state)
	s.mutex.Unlock()
	s.check()
}

// remove a stream from the fetch queue
// requires the mutex to be locked
func (s *rrSegFetcher) remove(state *ConsumeState) {
	s.streams = slices.DeleteFunc(s.streams,
		func(s *ConsumeState) bool { return s == state })
}

// find another state to work on
func (s *rrSegFetcher) findWork() *ConsumeState {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.outstanding >= s.window.Size() {
		return nil
	}

	// round-robin selection of the next stream to fetch
	next := func() *ConsumeState {
		if len(s.streams) == 0 {
			return nil
		}
		s.rrIndex = (s.rrIndex + 1) % len(s.streams)
		return s.streams[s.rrIndex]
	}

	// check all states for a workable one
	var state *ConsumeState = nil
	for i := 0; i < len(s.streams); i++ {
		check := next()
		if check == nil {
			return nil // nothing to do here
		}

		if check.IsComplete() {
			// lazy remove completed streams
			s.remove(check)

			// check if this was the last one
			if len(s.streams) == 0 {
				s.rrIndex = 0
				return nil
			}

			// check this index again
			s.rrIndex--
			if s.rrIndex < 0 {
				s.rrIndex = len(s.streams) - 1
			}
			i-- // length reduced
			continue
		}

		// if we don't know the segment count, wait for the first segment
		if check.segCnt == -1 && check.wnd[2] > 0 {
			// log.Infof("seg-fetcher: state wnd full for %s", check.fetchName)
			continue
		}

		// all interests are out
		if check.segCnt > 0 && check.wnd[2] >= check.segCnt {
			// log.Infof("seg-fetcher: all interests are out for %s", check.fetchName)
			continue
		}

		state = check
		break // found a state to work on
	}

	return state
}

func (s *rrSegFetcher) check() {
	for {
		state := s.findWork()
		if state == nil {
			return
		}

		// update window parameters
		seg := uint64(state.wnd[2])
		s.outstanding++
		state.wnd[2]++

		// queue outgoing interest for the next segment
		s.client.ExpressR(ndn.ExpressRArgs{
			Name: state.fetchName.Append(enc.NewSegmentComponent(seg)),
			Config: &ndn.InterestConfig{
				MustBeFresh: false,
			},
			Retries: 3,
			Callback: func(args ndn.ExpressCallbackArgs) {
				s.handleData(args, state)
			},
		})
	}
}

// handleData is called when a data packet is received.
// It is necessary that this function be called only from one goroutine - the engine.
// The notable exception here is when there is a timeout, which has a separate goroutine.
func (s *rrSegFetcher) handleData(args ndn.ExpressCallbackArgs, state *ConsumeState) {
	s.mutex.Lock()
	s.outstanding--
	s.mutex.Unlock()

	if state.IsComplete() {
		return
	}

	if args.Result == ndn.InterestResultError {
		state.finalizeError(fmt.Errorf("%w: fetch seg failed: %w", ndn.ErrNetwork, args.Error))
		return
	}

	if args.Result != ndn.InterestResultData {
		state.finalizeError(fmt.Errorf("%w: fetch seg failed with result: %s", ndn.ErrNetwork, args.Result))
		return
	}

	s.client.Validate(args.Data, args.SigCovered, func(valid bool, err error) {
		if !valid {
			state.finalizeError(fmt.Errorf("%w: validate seg failed: %w", ndn.ErrSecurity, err))
		} else {
			s.handleValidatedData(args, state)
		}
		s.check()
	})
}

func (s *rrSegFetcher) handleValidatedData(args ndn.ExpressCallbackArgs, state *ConsumeState) {
	// get the final block id if we don't know the segment count
	if state.segCnt == -1 { // TODO: can change?
		fbId, ok := args.Data.FinalBlockID().Get()
		if !ok {
			state.finalizeError(fmt.Errorf("%w: no FinalBlockId in object", ndn.ErrProtocol))
			return
		}

		if !fbId.IsSegment() {
			state.finalizeError(fmt.Errorf("%w: invalid FinalBlockId type=%d", ndn.ErrProtocol, fbId.Typ))
			return
		}

		state.segCnt = int(fbId.NumberVal()) + 1
		if state.segCnt > maxObjectSeg || state.segCnt <= 0 {
			state.finalizeError(fmt.Errorf("%w: invalid FinalBlockId=%d", ndn.ErrProtocol, state.segCnt))
			return
		}

		// resize output buffer
		state.content = make(enc.Wire, state.segCnt)
	}

	// process the incoming data
	name := args.Data.Name()

	// get segment number from name
	segComp := name.At(-1)
	if !segComp.IsSegment() {
		state.finalizeError(fmt.Errorf("%w: invalid segment number type=%d", ndn.ErrProtocol, segComp.Typ))
		return
	}

	// parse segment number
	segNum := int(segComp.NumberVal())
	if segNum >= state.segCnt || segNum < 0 {
		state.finalizeError(fmt.Errorf("%w: invalid segment number=%d", ndn.ErrProtocol, segNum))
		return
	}

	// copy the data into the buffer
	state.content[segNum] = args.Data.Content().Join()
	if state.content[segNum] == nil { // never
		panic("[BUG] consume: nil data segment")
	}

	// if this is the first outstanding segment, move windows
	if state.wnd[1] == segNum {
		for state.wnd[1] < state.segCnt && state.content[state.wnd[1]] != nil {
			state.wnd[1]++
		}

		if state.wnd[1] == state.segCnt {
			log.Debug(s, "Stream completed successfully", "name", state.fetchName)

			s.mutex.Lock()
			s.remove(state)
			s.mutex.Unlock()

			if !state.complete.Swap(true) {
				state.args.Callback(state) // complete
			}
			return
		}

		if state.args.OnProgress != nil && !state.IsComplete() {
			state.args.OnProgress(state)
		}
	}

	// if segNum%1000 == 0 {
	// 	log.Debugf("consume: %s [%d/%d] wnd=[%d,%d,%d] out=%d",
	// 		state.name, segNum, state.segCnt, state.wnd[0], state.wnd[1], state.wnd[2],
	// 		s.outstanding)
	// }
}
