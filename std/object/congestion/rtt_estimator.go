package congestion

import (
	"time"
)

// RTTEstimator provides an interface for estimating round-trip time.
type RTTEstimator interface {
	String() string

	EstimatedRTT() time.Duration // get the estimated RTT
	DeviationRTT() time.Duration // get the deviation of RTT

	AddMeasurement(sample time.Duration, retransmitted bool) // add a new RTT measurement
}
