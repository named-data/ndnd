package basic

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/named-data/ndnd/std/ndn"
)

type Timer struct{}

// (AI GENERATED DESCRIPTION): Creates and returns a new Timer instance initialized to its zero (empty) state.
func NewTimer() ndn.Timer {
	return Timer{}
}

// (AI GENERATED DESCRIPTION): Pauses execution for the specified duration by invoking `time.Sleep`.
func (Timer) Sleep(d time.Duration) {
	time.Sleep(d)
}

// (AI GENERATED DESCRIPTION): Schedules a callback to run after the given duration and returns a closure that cancels the scheduled call, returning an error if it has already been cancelled.
func (Timer) Schedule(d time.Duration, f func()) func() error {
	t := time.AfterFunc(d, f)
	return func() error {
		if t != nil {
			t.Stop()
			t = nil
			return nil
		} else {
			return fmt.Errorf("event has already been canceled")
		}
	}
}

// (AI GENERATED DESCRIPTION): Timer.Now returns the current local time from the system clock.
func (Timer) Now() time.Time {
	return time.Now()
}

// (AI GENERATED DESCRIPTION): Generates an 8‑byte cryptographically secure random nonce using crypto/rand and returns it as a byte slice.
func (Timer) Nonce() []byte {
	// After go1.20 rand.Seed does not need to be called manually.
	buf := make([]byte, 8)
	n, _ := rand.Read(buf) // Should always succeed
	return buf[:n]
}
