package face

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
)

type DummyFace struct {
	baseFace
	sendPkts []enc.Buffer
}

// (AI GENERATED DESCRIPTION): Creates a new DummyFace with an unsigned base face and initializes its send packet buffer to an empty slice.
func NewDummyFace() *DummyFace {
	return &DummyFace{
		baseFace: newBaseFace(true),
		sendPkts: make([]enc.Buffer, 0),
	}
}

// (AI GENERATED DESCRIPTION): Returns the static string `"dummy-face"` to represent the DummyFace.
func (f *DummyFace) String() string {
	return "dummy-face"
}

// (AI GENERATED DESCRIPTION): Opens the DummyFace by verifying that both error and packet callbacks are set, checking that it is not already running, and marking the face as running.
func (f *DummyFace) Open() error {
	if f.onError == nil || f.onPkt == nil {
		return fmt.Errorf("face callbacks are not set")
	}
	if f.running.Load() {
		return fmt.Errorf("face is already running")
	}
	f.running.Store(true)
	return nil
}

// (AI GENERATED DESCRIPTION): Stops the DummyFace by atomically setting its running flag to false, returning an error if it was already stopped.
func (f *DummyFace) Close() error {
	if !f.running.Swap(false) {
		return fmt.Errorf("face is not running")
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Adds the supplied packet(s) to the DummyFace’s send queue, concatenating multiple buffers into a single buffer when necessary, but only if the face is running; otherwise it returns an error.
func (f *DummyFace) Send(pkt enc.Wire) error {
	if !f.running.Load() {
		return fmt.Errorf("face is not running")
	}
	if len(pkt) == 1 {
		f.sendPkts = append(f.sendPkts, pkt[0])
	} else if len(pkt) >= 2 {
		newBuf := make(enc.Buffer, 0)
		for _, buf := range pkt {
			newBuf = append(newBuf, buf...)
		}
		f.sendPkts = append(f.sendPkts, newBuf)
	}
	return nil
}

// FeedPacket feeds a packet for the engine to consume
func (f *DummyFace) FeedPacket(pkt enc.Buffer) error {
	if !f.running.Load() {
		return fmt.Errorf("face is not running")
	}
	f.onPkt(pkt)

	// hack: yield to give engine time to process the packet
	time.Sleep(10 * time.Millisecond)
	return nil
}

// Consume consumes a packet from the engine
func (f *DummyFace) Consume() (enc.Buffer, error) {
	if !f.running.Load() {
		return nil, fmt.Errorf("face is not running")
	}

	// hack: yield to wait for packet to arrive
	time.Sleep(10 * time.Millisecond)

	if len(f.sendPkts) == 0 {
		return nil, fmt.Errorf("no packet to consume")
	}
	pkt := f.sendPkts[0]
	f.sendPkts = f.sendPkts[1:]
	return pkt, nil
}
