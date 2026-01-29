package congestion

import (
	"math"
	"sync"

	"github.com/named-data/ndnd/std/log"
)

// AIMDCongestionControl is an implementation of CongestionWindow using Additive Increase Multiplicative Decrease algorithm
type AIMDCongestionWindow struct {
	mutex sync.RWMutex

	window float64 // window size - float64 to allow percentage growth in congestion avoidance phase

	initCwnd    float64 // initial window size
	ssthresh    float64 // slow start threshold
	minSsthresh float64 // minimum slow start threshold
	aiStep      float64 // additive increase step
	mdCoef      float64 // multiplicative decrease coefficient
	resetCwnd   bool    // whether to reset cwnd after decrease
}

// TODO: should we bundle the parameters into an AIMDOption struct?

// (AI GENERATED DESCRIPTION): Creates a new AIMD congestion‑window instance initialized with the specified cwnd value and default parameters for slow‑start threshold, additive increase step, multiplicative decrease coefficient, etc.
func NewAIMDCongestionWindow(cwnd int) *AIMDCongestionWindow {
	return &AIMDCongestionWindow{
		window: float64(cwnd),

		initCwnd:    float64(cwnd),
		ssthresh:    math.MaxFloat64,
		minSsthresh: 2.0,
		aiStep:      1.0,
		mdCoef:      0.5,
		resetCwnd:   false, // defaults
	}
}

// log identifier
func (cw *AIMDCongestionWindow) String() string {
	return "aimd-congestion-window"
}

// (AI GENERATED DESCRIPTION): Returns the current size (in packets) of the AIMD congestion window.
func (cw *AIMDCongestionWindow) Size() int {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()

	return int(cw.window)
}

// (AI GENERATED DESCRIPTION): Increments the congestion window size using AIMD: adds a fixed step when below the slow‑start threshold and a fractional step proportional to 1/window when above it, while protecting the update with a mutex.
func (cw *AIMDCongestionWindow) IncreaseWindow() {
	cw.mutex.Lock()

	if cw.window < cw.ssthresh {
		cw.window += cw.aiStep // additive increase
	} else {
		cw.window += cw.aiStep / cw.window // congestion avoidance
	}

	cw.mutex.Unlock()

	log.Debug(cw, "Window size changes", "window", cw.window)
}

// (AI GENERATED DESCRIPTION): Decreases the congestion window size by computing a new slow‑start threshold using a multiplicative‑decrease coefficient (bounded by a minimum value) and then setting the window to either that threshold or the initial window if a reset flag is set.
func (cw *AIMDCongestionWindow) DecreaseWindow() {
	cw.mutex.Lock()

	cw.ssthresh = math.Max(cw.window*cw.mdCoef, cw.minSsthresh)

	if cw.resetCwnd {
		cw.window = cw.initCwnd
	} else {
		cw.window = cw.ssthresh
	}

	cw.mutex.Unlock()

	log.Debug(cw, "Window size changes", "window", cw.window)
}

// (AI GENERATED DESCRIPTION): Handles congestion signals by increasing the AIMD window on SigData, decreasing it on SigLoss or SigCongest, and leaving it unchanged for other signals.
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
