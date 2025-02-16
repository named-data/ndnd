package congestion

import (
	"math"
	"time"

	"github.com/named-data/ndnd/std/log"
)

// AIMDCongestionControl is an implementation of CongestionWindow using Additive Increase Multiplicative Decrease algorithm
type AIMDCongestionWindow struct {
	window 		int					// window size
	eventCh		chan WindowEvent	// channel for emitting window change event

	initCwnd	int					// initial window size
	ssthresh 	int					// slow start threshold
	minSsthresh int					// minimum slow start threshold
	aiStep		int					// additive increase step
	mdCoef		float64 			// multiplicative decrease coefficient
	resetCwnd	bool				// whether to reset cwnd after decrease
}

// TODO: should we bundle the parameters into an AIMDOption struct?

func NewAIMDCongestionWindow(cwnd int) *AIMDCongestionWindow {
	return &AIMDCongestionWindow{
		window: cwnd,
		eventCh: make(chan WindowEvent),

		initCwnd: cwnd,
		ssthresh: math.MaxInt,
		aiStep: 1,
		mdCoef: 0.5,
		resetCwnd: false,		// defaults
	}
}

// log identifier
func (cw *AIMDCongestionWindow) String() string {
	return "aimd-congestion-window"
}

func (cw *AIMDCongestionWindow) Size() int {
	return cw.window
}

func (cw *AIMDCongestionWindow) IncreaseWindow() {
	if cw.window < cw.ssthresh {
		cw.window += cw.aiStep					// additive increase
	} else {
		cw.window += cw.aiStep / cw.window		// congestion avoidance

		// note: the congestion avoidance formula differs from RFC 5681 Section 3.1
		// 	recommendations and is borrowed from ndn-tools/catchunks, check
		// https://github.com/named-data/ndn-tools/blob/130975c4be69d126fede77d47a50580d5e8b25b0/tools/chunks/catchunks/pipeline-interests-aimd.cpp#L45
	}

	cw.EmitWindowEvent(time.Now(), cw.window)	// window change signal
}

func (cw *AIMDCongestionWindow) DecreaseWindow() {
	cw.ssthresh = int(math.Max(float64(cw.window) * cw.mdCoef, float64(cw.minSsthresh)))

	if cw.resetCwnd {
		cw.window = cw.initCwnd
	} else {
		cw.window = cw.ssthresh
	}

	cw.EmitWindowEvent(time.Now(), cw.window)	// window change signal
}

func (cw *AIMDCongestionWindow) EventChannel() <-chan WindowEvent {
	return cw.eventCh
}

func (cw *AIMDCongestionWindow) HandleSignal(signal CongestionSignal) {
	switch signal {
	case SigData:
		cw.IncreaseWindow()
	case SigLoss, SigCongest:
		cw.DecreaseWindow()
	default:
		// no-op
	}
}

func (cw *AIMDCongestionWindow) EmitWindowEvent(age time.Time, cwnd int) {
	// non-blocking send to the channel
	select {
	case cw.eventCh <- WindowEvent{age: age, cwnd: cwnd}:
	default:
		// if the channel is full, we log the change event
		log.Debug(cw, "Window size changes", "window", cw.window)
	}
}