package core

import (
	"sync/atomic"
	"time"
)

// ClockResolution is the precision of Now().
const ClockResolution = 10 * time.Millisecond

var clockStart = time.Now()
var clockOffset atomic.Int64 // nanoseconds since clockStart

func init() {
	go func() {
		for range time.Tick(ClockResolution) {
			clockOffset.Store(int64(time.Since(clockStart)))
		}
	}()
}

// Now returns the current time with ClockResolution precision.
// It is much cheaper than time.Now() and is monotonic, so it is
// unaffected by changes to the wall clock.
// Use it in the packet processing path where precision is not needed.
func Now() time.Time {
	return clockStart.Add(time.Duration(clockOffset.Load()))
}
