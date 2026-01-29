package congestion

import (
	"math"
	"sync"
	"time"

	"github.com/named-data/ndnd/std/log"
)

// CUBICCongestionWindow is an implementation of CongestionWindow using CUBIC algorithm
// ref: https://tools.ietf.org/html/rfc8312
type CUBICCongestionWindow struct {
	mutex sync.RWMutex

	window float64 // window size

	rttEstimator *RTTEstimator // RTT estimator

	ssthresh        float64   // slow start threshold
	minSsthresh     float64   // minimum slow start threshold
	aiStep          float64   // additive increase step
	mdCoef          float64   // multiplicative decrease coefficient
	c               float64   // aggressiveness factor
	windowMax       float64   // maximum window size
	lastWindowMax   float64   // last maximum window size
	fastConvergence bool      // whether to use fast convergence
	tcpFriendliness bool      // whether to use TCP-friendly mode
	lastDecrease    time.Time // time of last window-decrease event
}

// NewCUBICCongestionWindow creates a new CUBICCongestionWindow.
// rttEstimator is the RTT estimator to use, or nil if not available.
func NewCUBICCongestionWindow(cwnd int, rttEstimator *RTTEstimator) *CUBICCongestionWindow {
	return &CUBICCongestionWindow{
		window: float64(cwnd),

		rttEstimator: rttEstimator,

		ssthresh:        math.MaxFloat64,
		minSsthresh:     2.0,
		aiStep:          1.0,
		mdCoef:          0.7,
		c:               0.4,
		windowMax:       float64(cwnd),
		lastWindowMax:   float64(cwnd),
		fastConvergence: true,
		tcpFriendliness: false,
		lastDecrease:    time.Now(),
	}
}

// (AI GENERATED DESCRIPTION): Returns the string “cubic-congestion-window” to represent a CUBICCongestionWindow instance.
func (cw *CUBICCongestionWindow) String() string {
	return "cubic-congestion-window"
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the current congestion window size of the CUBIC congestion controller as an integer.
func (cw *CUBICCongestionWindow) Size() int {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()

	return int(cw.window)
}

// Cubic update algorithm
func (cw *CUBICCongestionWindow) CubicUpdate() {
	rtt := 0.0
	if cw.rttEstimator != nil {
		rtt = (*cw.rttEstimator).EstimatedRTT().Seconds() // estimated RTT
	}

	t := time.Since(cw.lastDecrease).Abs().Seconds()        // time since last decrease
	k := math.Cbrt((cw.windowMax * (1 - cw.mdCoef)) / cw.c) // time takes to increase window to windowMax

	// estimated cubic window size
	wCubic := cw.c*math.Pow(t+rtt-k, 3) + cw.windowMax

	// TCP-friendly mode
	if cw.tcpFriendliness && cw.rttEstimator != nil {
		// TCP-friendly window size
		wEst := cw.windowMax*cw.mdCoef + 3*(1-cw.mdCoef)/(1+cw.mdCoef)*t/rtt

		// update window size
		if cw.window < wEst {
			cw.window = wEst
			log.Debug(cw, "TCP-friendly increment", "wEst", wEst, "window", cw.window)
			return
		}
	}

	// note: (wCubic - cw.window) can sometimes be negative, which decreases the window size.
	//     As an effort to improve clarity and performance, we clamp the value to be non-negative.
	//     This behavior is not specified in the original RFC.
	cw.window += math.Max((wCubic-cw.window)/cw.window, 0)
	log.Debug(cw, "Cubic increment", "wCubic", wCubic, "window", cw.window)
}

// (AI GENERATED DESCRIPTION): Increments the congestion window size: during slow‑start it adds `aiStep` until the threshold `ssthresh`, then invokes `CubicUpdate` for CUBIC congestion‑avoidance.
func (cw *CUBICCongestionWindow) IncreaseWindow() {
	cw.mutex.Lock()

	// slow start
	if cw.window < cw.ssthresh {
		cw.window += cw.aiStep
	} else {
		// congestion avoidance
		cw.CubicUpdate()
	}

	cw.mutex.Unlock()

	log.Debug(cw, "Window size changes", "window", cw.window)
}

// (AI GENERATED DESCRIPTION): Decreases the congestion window and slow‑start threshold using a multiplicative‑decrease rule, updates the window maximum for fast convergence if enabled, and records the time of the last reduction.
func (cw *CUBICCongestionWindow) DecreaseWindow() {
	cw.mutex.Lock()

	// update windowMax
	cw.windowMax = cw.window

	// faster convergence
	if cw.windowMax < cw.lastWindowMax && cw.fastConvergence {
		cw.lastWindowMax = cw.windowMax
		cw.windowMax *= (1 + cw.mdCoef) / 2 // further decrease windowMax
	} else {
		cw.lastWindowMax = cw.windowMax
	}

	// decrease window size
	cw.ssthresh = math.Max(cw.window*cw.mdCoef, cw.minSsthresh)
	cw.window = math.Max(cw.window*cw.mdCoef, 1)
	cw.lastDecrease = time.Now()

	cw.mutex.Unlock()

	log.Debug(cw, "Window size changes", "window", cw.window)
}

// (AI GENERATED DESCRIPTION): Adjusts the congestion window in response to a congestion signal, increasing the window on data reception and decreasing it on loss or congestion indications.
func (cw *CUBICCongestionWindow) HandleSignal(signal CongestionSignal) {
	switch signal {
	case SigData:
		cw.IncreaseWindow()
	case SigLoss, SigCongest:
		cw.DecreaseWindow()
	default:
		// no-op
	}
}
