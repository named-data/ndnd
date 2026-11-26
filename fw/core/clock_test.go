package core

import (
	"testing"
	"time"
)

// (AI GENERATED DESCRIPTION): Tests that the coarse clock advances and stays within a few ticks of time.Now().
func TestNow(t *testing.T) {
	time.Sleep(3 * ClockResolution)
	for range 5 {
		diff := time.Since(Now())
		if diff < 0 || diff > 5*ClockResolution {
			t.Fatalf("coarse clock is off by %v", diff)
		}
		time.Sleep(ClockResolution)
	}
}
