package object

import (
	"fmt"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
)

// round-robin based segment fetcher
// no lock is needed because there is a single goroutine that does both
// check() and handleData() in the client class
type rrSegFetcher struct {
	// ref to parent
	client *Client
	// list of active streams
	streams []*ConsumeState
	// round robin index
	rrIndex int
	// number of outstanding interests
	outstanding int
	// window size
	window int
}

type rrSegHandleDataArgs struct {
	state *ConsumeState
	args  ndn.ExpressCallbackArgs
}

func newRrSegFetcher(client *Client) rrSegFetcher {
	return rrSegFetcher{
		client:      client,
		streams:     make([]*ConsumeState, 0),
		window:      10,
		outstanding: 0,
	}
}

// log identifier
func (s *rrSegFetcher) String() string {
	return "client-seg"
}

// add a stream to the fetch queue
func (s *rrSegFetcher) add(state *ConsumeState) {
	log.Debug(s, "Adding stream to fetch queue", "name", state.fetchName)
	s.streams = append(s.streams, state)
	s.queueCheck()
}

// remove a stream from the fetch queue
func (s *rrSegFetcher) remove(state *ConsumeState) {
	for i, stream := range s.streams {
		if stream == state {
			s.streams = append(s.streams[:i], s.streams[i+1:]...)
			return
		}
	}
}

// round-robin selection of the next stream to fetch
func (s *rrSegFetcher) next() *ConsumeState {
	if len(s.streams) == 0 {
		return nil
	}
	s.rrIndex = (s.rrIndex + 1) % len(s.streams)
	return s.streams[s.rrIndex]
}

// queue a check for more work
func (s *rrSegFetcher) queueCheck() {
	select {
	case s.client.segcheck <- true:
	default: // already scheduled
	}
}

// check for more work
func (s *rrSegFetcher) doCheck() {
	if s.outstanding >= s.window {
		return
	}

	// check all states for a workable one
	var state *ConsumeState = nil
	for i := 0; i < len(s.streams); i++ {
		check := s.next()
		if check == nil {
			return // nothing to do here
		}

		if check.complete {
			// lazy remove completed streams
			s.remove(check)

			// check if this was the last one
			if len(s.streams) == 0 {
				s.rrIndex = 0
				return
			}

			// check this index again
			s.rrIndex--
			if s.rrIndex < 0 {
				s.rrIndex = len(s.streams) - 1
			}
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

	// exit if there's nothing to work on
	if state == nil {
		return
	}

	// update window parameters
	seg := uint64(state.wnd[2])
	s.outstanding++
	state.wnd[2]++
	defer s.doCheck()

	// queue outgoing interest for the next segment
	args := ExpressRArgs{
		Name: state.fetchName.Append(enc.NewSegmentComponent(seg)),
		Config: &ndn.InterestConfig{
			MustBeFresh: false,
		},
		Retries: 3,
	}
	s.client.ExpressR(args, func(args ndn.ExpressCallbackArgs) {
		s.client.seginpipe <- rrSegHandleDataArgs{state: state, args: args}
	})
}

// handle incoming data
func (s *rrSegFetcher) handleData(args ndn.ExpressCallbackArgs, state *ConsumeState) {
	s.outstanding--
	s.queueCheck()

	if state.complete {
		return
	}

	if args.Result == ndn.InterestResultError {
		state.finalizeError(fmt.Errorf("consume: fetch failed with error %v", args.Error))
		return
	}

	if args.Result != ndn.InterestResultData {
		state.finalizeError(fmt.Errorf("consume: fetch failed with result %d", args.Result))
		return
	}

	// get the final block id if we don't know the segment count
	if state.segCnt == -1 { // TODO: can change?
		fbId := args.Data.FinalBlockID()
		if fbId == nil {
			state.finalizeError(fmt.Errorf("consume: no FinalBlockId in object"))
			return
		}

		if fbId.Typ != enc.TypeSegmentNameComponent {
			state.finalizeError(fmt.Errorf("consume: invalid FinalBlockId type=%d", fbId.Typ))
			return
		}

		state.segCnt = int(fbId.NumberVal()) + 1
		if state.segCnt > maxObjectSeg || state.segCnt <= 0 {
			state.finalizeError(fmt.Errorf("consume: invalid FinalBlockId=%d", state.segCnt))
			return
		}

		// resize output buffer
		state.content = make(enc.Wire, state.segCnt)
	}

	// process the incoming data
	name := args.Data.Name()

	// get segment number from name
	segComp := name[len(name)-1]
	if segComp.Typ != enc.TypeSegmentNameComponent {
		state.finalizeError(fmt.Errorf("consume: invalid segment number type=%d", segComp.Typ))
		return
	}

	// parse segment number
	segNum := int(segComp.NumberVal())
	if segNum >= state.segCnt || segNum < 0 {
		state.finalizeError(fmt.Errorf("consume: invalid segment number=%d", segNum))
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
			state.complete = true
			s.remove(state)
		}

		state.args.Callback(state) // progress
	}

	// if segNum%1000 == 0 {
	// 	log.Debugf("consume: %s [%d/%d] wnd=[%d,%d,%d] out=%d",
	// 		state.name, segNum, state.segCnt, state.wnd[0], state.wnd[1], state.wnd[2],
	// 		s.outstanding)
	// }
}
