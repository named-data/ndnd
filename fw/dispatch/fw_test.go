package dispatch

import (
	"testing"

	"github.com/named-data/ndnd/fw/defn"
)

type dummyThread struct{}

func (dummyThread) String() string                  { return "dummy" }
func (dummyThread) QueueData(*defn.Pkt)             {}
func (dummyThread) QueueInterest(*defn.Pkt)         {}
func (dummyThread) Counters() defn.FWThreadCounters { return defn.FWThreadCounters{} }

// GetFWThread is called with a thread ID taken from the PIT token of an
// incoming Data packet, so out-of-range IDs must return nil instead of panicking.
func TestGetFWThreadBounds(t *testing.T) {
	InitializeFWThreads([]FWThread{dummyThread{}, dummyThread{}})
	defer InitializeFWThreads(nil)

	if GetFWThread(0) == nil || GetFWThread(1) == nil {
		t.Fatal("expected valid thread for in-range ID")
	}
	for _, id := range []int{-1, 2, 3, 65535} {
		if GetFWThread(id) != nil {
			t.Fatalf("expected nil for out-of-range ID %d", id)
		}
	}
}
