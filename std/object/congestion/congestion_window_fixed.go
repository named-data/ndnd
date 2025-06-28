package congestion

// FixedCongestionControl is an implementation of CongestionWindow with a fixed window size that does not change in response to signals or events.
type FixedCongestionWindow struct {
	window int // window size
}

func NewFixedCongestionWindow(cwnd int) *FixedCongestionWindow {
	return &FixedCongestionWindow{
		window: cwnd,
	}
}

// log identifier
func (cw *FixedCongestionWindow) String() string {
	return "fixed-congestion-window"
}

func (cw *FixedCongestionWindow) Size() int {
	return cw.window
}

func (cw *FixedCongestionWindow) IncreaseWindow() {
	// intentionally left blank: window size is fixed
}

func (cw *FixedCongestionWindow) DecreaseWindow() {
	// intentionally left blank: window size is fixed
}

func (cw *FixedCongestionWindow) HandleSignal(signal CongestionSignal) {
	// intentionally left blank: fixed CW doesn't respond to signals
}
