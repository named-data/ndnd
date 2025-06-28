package congestion

// CongestionSignal represents signals to adjust the congestion window.
type CongestionSignal int

const (
	SigData    = iota // data is fetched
	SigLoss           // data loss detected
	SigCongest        // congestion detected (e.g. NACK with a reason of congestion)
)

// CongestionWindow provides an interface for congestion control that manages a window
type CongestionWindow interface {
	String() string

	HandleSignal(signal CongestionSignal) // signal handler

	Size() int
	IncreaseWindow()
	DecreaseWindow()
}
