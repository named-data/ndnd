package object

import (
	"container/list"
	"fmt"
	"slices"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	cong "github.com/named-data/ndnd/std/object/congestion"
	"github.com/named-data/ndnd/std/utils"
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
	window cong.CongestionWindow
	// retransmission queue
	retxQueue *list.List
	// remaining segments to be transmitted by state
	txCounter map[*ConsumeState]int
	// maximum number of retries
	maxRetries int
}

// retxEntry represents an entry in the retransmission queue
// it contains the consumer state, segment number and the number of retries left for the segment
type retxEntry struct {
	state *ConsumeState
	seg uint64
	retries int
}

func newRrSegFetcher(client *Client) rrSegFetcher {
	return rrSegFetcher{
		mutex:       sync.RWMutex{},
		client:      client,
		streams:     make([]*ConsumeState, 0),
		window:      cong.NewFixedCongestionWindow(100),
		outstanding: 0,
		retxQueue: 	 list.New(),
		txCounter: 	 make(map[*ConsumeState]int),
		maxRetries:  3,
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
		log.Debug(nil, "Checking for work")

		// check if the window is full
		if s.IsCongested() {
			log.Debug(nil, "Window full", "size", s.window.Size())
			return	// no need to generate new interests
		}

		var (
			state   *ConsumeState
			seg     uint64
			retries int = s.maxRetries // TODO: make it configurable
		)

		// if there are retransmissions, handle them first
		if s.retxQueue.Len() > 0 {
			log.Debug(nil, "Retransmitting")

			retx := s.retxQueue.Remove(s.retxQueue.Front()).(*retxEntry)
			state = retx.state
			seg = retx.seg
			retries = retx.retries

		} else { // if no retransmissions, find a stream to work on
			state = s.findWork()
			if state == nil {
				return
			}

			// update window parameters
			seg = uint64(state.wnd[2])
			state.wnd[2]++
		}

		// build interest
		name := state.fetchName.Append(enc.NewSegmentComponent(seg))
		config := &ndn.InterestConfig{
			MustBeFresh: false,
			Nonce: utils.ConvertNonce(s.client.engine.Timer().Nonce()),	// new nonce for each call
		}
		var appParam enc.Wire = nil
		var signer ndn.Signer = nil

		log.Debug(nil, "Building interest", "name", name, "config", config)
		interest, err := s.client.Engine().Spec().MakeInterest(name, config, appParam, signer)
		if err != nil {
			s.handleResult(ndn.ExpressCallbackArgs{
				Result: ndn.InterestResultError,
				Error: err,
			}, state, seg, retries)
			return
		}

		// build express callback function
		callback := func(args ndn.ExpressCallbackArgs) {
			s.handleResult(args, state, seg, retries)
		}

		// express interest
		log.Debug(nil, "Expressing interest", "name", interest.FinalName)
		err = s.client.Engine().Express(interest, callback)
		if err != nil {
			s.handleResult(ndn.ExpressCallbackArgs{
				Result: ndn.InterestResultError,
				Error: err,
			}, state, seg, retries)
			return
		}

		// increment outstanding interest count
		s.mutex.Lock()
		s.outstanding++
		s.mutex.Unlock()
	}
}

// handleResult is called when the result for an interest is ready.
// It is necessary that this function be called only from one goroutine - the engine.
func (s *rrSegFetcher) handleResult(args ndn.ExpressCallbackArgs, state *ConsumeState, seg uint64, retries int) {
	// get the name of the interest
	var interestName enc.Name = state.fetchName.Append(enc.NewSegmentComponent(seg))
	log.Debug(nil, "Parsing interest result", "name", interestName)

	// decrement outstanding interest count
	s.mutex.Lock()
	s.outstanding--
	s.mutex.Unlock()

	if state.IsComplete() {
		return
	}

	// handle the result
	switch args.Result {
	case ndn.InterestResultTimeout:
		log.Debug(nil, "Interest timeout", "name", interestName)

		s.window.HandleSignal(cong.SigLoss)
		s.enqueueForRetransmission(state, seg, retries - 1)

	case ndn.InterestResultNack:
		log.Debug(nil, "Interest nack'd", "name", interestName)

		switch args.NackReason {
		case spec.NackReasonDuplicate:
			// ignore Nack for duplicates
		case spec.NackReasonCongestion:
			// congestion signal
			s.window.HandleSignal(cong.SigCongest)
			s.enqueueForRetransmission(state, seg, retries - 1)
		default:
			// treat as irrecoverable error for now
			state.finalizeError(fmt.Errorf("%w: fetch seg failed with result: %s", ndn.ErrNetwork, args.Result))
		}

	case ndn.InterestResultData:	// data is successfully retrieved
		s.handleData(args, state)

	default:	// treat as irrecoverable error for now
		state.finalizeError(fmt.Errorf("%w: fetch seg failed with result: %s", ndn.ErrNetwork, args.Result))
	}
}

// handleData is called when the interest result is processed and the data is ready to be validated.
// It is necessary that this function be called only from one goroutine - the engine.
// The notable exception here is when there is a timeout, which has a separate goroutine.
func (s *rrSegFetcher) handleData(args ndn.ExpressCallbackArgs, state *ConsumeState) {
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
		s.txCounter[state] = state.segCnt			// number of segments to be transmitted for this state
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

	// decrease transmission counter
	s.mutex.Lock()
	s.txCounter[state]--
	s.mutex.Unlock()

	// if this is the first outstanding segment, move windows
	if state.wnd[1] == segNum {
		for state.wnd[1] < state.segCnt && state.content[state.wnd[1]] != nil {
			state.wnd[1]++
		}

		if state.wnd[1] == state.segCnt && s.txCounter[state] == 0 {
			log.Debug(s, "Stream completed successfully", "name", state.fetchName)

			s.mutex.Lock()
			s.remove(state)
			delete(s.txCounter, state)
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

// enqueueForRetransmission enqueues a segment for retransmission
// it registers retries and treats exhausted retries as irrecoverable errors
func (s *rrSegFetcher) enqueueForRetransmission(state *ConsumeState, seg uint64, retries int) {
	if (retries == 0) {	// retransmission exhausted
		state.finalizeError(fmt.Errorf("%w: retries exhausted, segment number=%d", ndn.ErrNetwork, seg))
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.retxQueue.PushBack(&retxEntry{state, seg, retries})
}