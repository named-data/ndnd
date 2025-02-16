package congestion

// FixedCongestionControl is an implementation of CongestionWindow using Additive Increase Multiplicative Decrease algorithm
type FixedCongestionWindow struct {
	window 		int					// window size
	eventCh		chan WindowEvent	// channel for emitting window change event
}

func NewFixedCongestionWindow(cwnd int) *FixedCongestionWindow {
	return &FixedCongestionWindow{
		window: cwnd,
		eventCh: make(chan WindowEvent),
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

func (cw *FixedCongestionWindow) EventChannel() <-chan WindowEvent {
	return cw.eventCh
}

func (cw *FixedCongestionWindow) HandleSignal(signal CongestionSignal) {
	// intentionally left blank: fixed CW doesn't respond to signals
}