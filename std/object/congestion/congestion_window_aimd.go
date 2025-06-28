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

func (cw *AIMDCongestionWindow) Size() int {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()

	return int(cw.window)
}

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
