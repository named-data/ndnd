package congestion

import "time"

// Congestion control signals
type CongestionSignal int
const (
	// TODO: signals
	SigRecv = iota	// segment received
	SigLoss			// loss detected
	SigCongest		// congestion detected
)

// Congestion window change event
type WindowEvent struct {
	age		time.Time	// time of the event
	cwnd 	int			// new window size
}

// CongestionWindow provides an interface for congestion control that manages a window size
type CongestionWindow interface {
	String() string

	EventChannel() <-chan WindowEvent		// where window events are emitted
	HandleSignal(signal CongestionSignal)	// signal handler

	Size() int
	IncreaseWindow()
	DecreaseWindow()
}