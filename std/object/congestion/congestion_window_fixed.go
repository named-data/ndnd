package congestion

// FixedCongestionControl is an implementation of CongestionWindow with a fixed window size that does not change in response to signals or events.
type FixedCongestionWindow struct {
	window int // window size
}

// (AI GENERATED DESCRIPTION): Initializes a FixedCongestionWindow instance with the specified congestion‑window size.
func NewFixedCongestionWindow(cwnd int) *FixedCongestionWindow {
	return &FixedCongestionWindow{
		window: cwnd,
	}
}

// log identifier
func (cw *FixedCongestionWindow) String() string {
	return "fixed-congestion-window"
}

// (AI GENERATED DESCRIPTION): Returns the current size of the fixed congestion window.
func (cw *FixedCongestionWindow) Size() int {
	return cw.window
}

// (AI GENERATED DESCRIPTION): Does nothing – keeps the congestion window size fixed by intentionally not increasing it.
func (cw *FixedCongestionWindow) IncreaseWindow() {
	// intentionally left blank: window size is fixed
}

// (AI GENERATED DESCRIPTION): No‑op: the congestion window is fixed, so this method intentionally performs no action when a decrease is requested.
func (cw *FixedCongestionWindow) DecreaseWindow() {
	// intentionally left blank: window size is fixed
}

// (AI GENERATED DESCRIPTION): Does nothing in response to congestion signals, keeping the congestion window fixed.
func (cw *FixedCongestionWindow) HandleSignal(signal CongestionSignal) {
	// intentionally left blank: fixed CW doesn't respond to signals
}
