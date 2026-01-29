package basic_test

import (
	"testing"
	"time"

	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests that the DummyTimer starts at epoch zero and correctly advances its internal clock when time is moved forward.
func TestClock(t *testing.T) {
	tu.SetT(t)

	tm := basic_engine.NewDummyTimer()
	require.Equal(t, tu.NoErr(time.Parse(time.RFC3339, "1970-01-01T00:00:00Z")), tm.Now())
	tm.MoveForward(10 * time.Second)
	require.Equal(t, tu.NoErr(time.Parse(time.RFC3339, "1970-01-01T00:00:10Z")), tm.Now())
	tm.MoveForward(50 * time.Second)
	require.Equal(t, tu.NoErr(time.Parse(time.RFC3339, "1970-01-01T00:01:00Z")), tm.Now())
}

// (AI GENERATED DESCRIPTION): Tests the DummyTimer's scheduling logic by scheduling callbacks at various future times and confirming they execute in the correct order as the timer is advanced.
func TestSchedule(t *testing.T) {
	tu.SetT(t)

	tm := basic_engine.NewDummyTimer()
	val := 0
	tm.Schedule(10*time.Second, func() {
		val = 1
	})
	require.Equal(t, 0, val)
	tm.MoveForward(11 * time.Second)
	require.Equal(t, 1, val)
	lst := []int{0, 0, 0}
	tm.Schedule(10*time.Second, func() {
		lst[0] = 1
	})
	tm.Schedule(20*time.Second, func() {
		lst[1] = 2
	})
	tm.Schedule(15*time.Second, func() {
		lst[2] = 3
	})
	tm.MoveForward(11 * time.Second)
	require.Equal(t, []int{1, 0, 0}, lst)
	tm.MoveForward(5 * time.Second)
	require.Equal(t, []int{1, 0, 3}, lst)
	tm.MoveForward(5 * time.Second)
	require.Equal(t, []int{1, 2, 3}, lst)
}

// (AI GENERATED DESCRIPTION): Tests that cancelling a scheduled timer event prevents its execution, ensuring that cancelled events do not fire even when multiple events are scheduled.
func TestCancel(t *testing.T) {
	tu.SetT(t)

	tm := basic_engine.NewDummyTimer()
	val := 0
	cancel := tm.Schedule(10*time.Second, func() {
		val = 1
	})
	require.Equal(t, 0, val)
	cancel()
	tm.MoveForward(11 * time.Second)
	require.Equal(t, 0, val)

	lst := []int{0, 0, 0}
	tm.Schedule(10*time.Second, func() {
		lst[0] = 1
	})
	tm.Schedule(20*time.Second, func() {
		lst[1] = 2
	})
	cancel = tm.Schedule(15*time.Second, func() {
		lst[2] = 3
	})
	cancel()
	tm.MoveForward(21 * time.Second)
	require.Equal(t, []int{1, 2, 0}, lst)
}
