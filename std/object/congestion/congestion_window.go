package congestion

import "time"

// CongestionSignal represents signals to adjust the congestion window.
type CongestionSignal int

const (
	SigData = iota	// data is fetched
	SigLoss			// data loss detected
	SigTimeout		// timeout detected
	SigCongest		// congestion detected (e.g. NACK with a reason of congestion)
)

// Congestion window change event
type WindowEvent struct {
	age		time.Time	// time of the event
	cwnd 	int			// new window size
}

// CongestionWindow provides an interface for congestion control that manages a window
type CongestionWindow interface {
	String() string

	EventChannel() <-chan WindowEvent		// where window events are emitted
	HandleSignal(signal CongestionSignal)	// signal handler

	Size() int
	IncreaseWindow()
	DecreaseWindow()
}