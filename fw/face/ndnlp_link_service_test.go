package face

import (
	"testing"

	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A single fragment with an attacker-controlled FragCount must not cause
// an unbounded reassembly buffer allocation.
func TestReassembleFragCountBound(t *testing.T) {
	l := &NDNLPLinkService{}
	frame := &defn.FwLpPacket{Fragment: enc.Wire{[]byte{0x01}}}

	// 1<<22 fragment slots would allocate a ~96MB slice for one tiny fragment
	frag := l.reassemble(frame, 1, 0, 1<<22)
	assert.Nil(t, frag)
	for i := range l.reassemblyBuffers {
		assert.Nilf(t, l.reassemblyBuffers[i].buffer,
			"buffer %d allocated %d fragment slots for an oversized FragCount",
			i, len(l.reassemblyBuffers[i].buffer))
	}
}

// A frame with FragIndex greater than its Sequence must be dropped before
// baseSequence is computed (uint64 underflow) and no state may be allocated.
func TestReassemblyFragIndexExceedsSequence(t *testing.T) {
	l := &NDNLPLinkService{options: MakeNDNLPLinkServiceOptions()}
	lp := &defn.FwLpPacket{
		Fragment:  enc.Wire{[]byte{0x01}},
		Sequence:  optional.Some(uint64(0)),
		FragIndex: optional.Some(uint64(1)),
		FragCount: optional.Some(uint64(2)),
	}
	pkt := defn.FwPacket{LpPacket: lp}
	frameWire := pkt.Encode()
	require.NotNil(t, frameWire)

	l.handleIncomingFrame(frameWire.Join())
	for i := range l.reassemblyBuffers {
		assert.Nilf(t, l.reassemblyBuffers[i].buffer,
			"buffer %d allocated (sequence %d) for an invalid FragIndex/Sequence pair",
			i, l.reassemblyBuffers[i].sequence)
	}
}

// A legitimate fragmented packet must still reassemble: fragments arrive in
// order, the completed wire is returned, and the buffer is freed.
func TestReassembleValidSequence(t *testing.T) {
	l := &NDNLPLinkService{}
	f0 := &defn.FwLpPacket{Fragment: enc.Wire{[]byte{0x01}}}
	f1 := &defn.FwLpPacket{Fragment: enc.Wire{[]byte{0x02}}}

	assert.Nil(t, l.reassemble(f0, 100, 0, 2)) // incomplete
	full := l.reassemble(f1, 100, 1, 2)
	require.NotNil(t, full)
	assert.Equal(t, enc.Wire{[]byte{0x01}, []byte{0x02}}, full)

	// buffer freed after completion
	for i := range l.reassemblyBuffers {
		assert.Nil(t, l.reassemblyBuffers[i].buffer)
	}
}
