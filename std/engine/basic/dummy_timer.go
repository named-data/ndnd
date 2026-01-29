package basic

import (
	"fmt"
	"sync"
	"time"
)

type dummyEvent struct {
	t time.Time
	f func()
}

type DummyTimer struct {
	now    time.Time
	events []dummyEvent
	// Lock is not an very important thing because:
	//   1. Basic engine itself is single-threaded
	//   2. This timer is for test only, and there is a low chance for race.
	lock sync.Mutex
}

// (AI GENERATED DESCRIPTION): Creates a new DummyTimer initialized to the Unix epoch (1970‑01‑01T00:00:00Z) with an empty event queue.
func NewDummyTimer() *DummyTimer {
	now, err := time.Parse(time.RFC3339, "1970-01-01T00:00:00Z")
	if err != nil {
		return nil
	}
	return &DummyTimer{
		now:    now,
		events: make([]dummyEvent, 0),
	}
}

// (AI GENERATED DESCRIPTION): Returns the time value stored in the DummyTimer instance.
func (tm *DummyTimer) Now() time.Time {
	return tm.now
}

// (AI GENERATED DESCRIPTION): Advances the dummy timer forward by the given duration, executes any scheduled events whose time has passed, and updates the internal event list in a thread‑safe manner.
func (tm *DummyTimer) MoveForward(d time.Duration) {
	events := func() []dummyEvent {
		tm.lock.Lock()
		defer tm.lock.Unlock()
		tm.now = tm.now.Add(d)
		ret := make([]dummyEvent, len(tm.events))
		copy(ret, tm.events)
		return ret
	}()

	// Run events
	for i, e := range events {
		if e.f != nil {
			if e.t.Before(tm.now) {
				e.f()
				events[i].f = nil
			}
		}
	}

	func() {
		tm.lock.Lock()
		defer tm.lock.Unlock()
		tm.events = events
	}()
}

// (AI GENERATED DESCRIPTION): Schedules a callback to run after a specified duration and returns a function that can cancel the scheduled event if it has not yet fired.
func (tm *DummyTimer) Schedule(d time.Duration, f func()) func() error {
	t := tm.now.Add(d)
	tm.lock.Lock()
	defer tm.lock.Unlock()

	idx := len(tm.events)
	for i := range tm.events {
		if tm.events[i].f == nil {
			idx = i
			break
		}
	}
	if idx == len(tm.events) {
		tm.events = append(tm.events, dummyEvent{
			t: t,
			f: f,
		})
	} else {
		tm.events[idx] = dummyEvent{
			t: t,
			f: f,
		}
	}

	return func() error {
		if t.Before(tm.now) {
			return nil // Already past
		}
		if idx < len(tm.events) && tm.events[idx].t.Equal(t) && tm.events[idx].f != nil {
			tm.lock.Lock()
			defer tm.lock.Unlock()
			tm.events[idx].f = nil
			return nil
		} else {
			return fmt.Errorf("event has already been canceled")
		}
	}
}

// (AI GENERATED DESCRIPTION): Sleeps for the specified duration by scheduling a callback in the DummyTimer and blocking until that callback signals completion.
func (tm *DummyTimer) Sleep(d time.Duration) {
	ch := make(chan struct{})
	tm.Schedule(d, func() {
		ch <- struct{}{}
		close(ch)
	})
	<-ch
}

// (AI GENERATED DESCRIPTION): Returns a fixed 8‑byte nonce (0x01…0x08) for use by the dummy timer during testing.
func (*DummyTimer) Nonce() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
}
