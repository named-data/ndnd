package io

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A stream whose second frame declares a TLV-LENGTH of 2^64-1.
// The framer must reject it, not wrap int(len) negative and hand a
// garbage "frame" to the caller.
func TestReadTlvStreamRejectsHugeLength(t *testing.T) {
	var buf bytes.Buffer
	// one valid tiny frame: type 0x64, length 0x01, one payload byte
	buf.Write([]byte{0x64, 0x01, 0x00})
	// malicious frame: type 0x64, length encoded in 8 bytes as MaxUint64
	buf.Write([]byte{0x64, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	buf.Write(make([]byte, 64)) // trailing garbage

	var frames [][]byte
	err := ReadTlvStream(&buf, func(b []byte) bool {
		frames = append(frames, append([]byte(nil), b...))
		return true
	}, nil)

	assert.Error(t, err, "oversized TLV-LENGTH must abort the stream")
	assert.Equal(t, 1, len(frames), "only the valid frame may be delivered")
	assert.Equal(t, []byte{0x64, 0x01, 0x00}, frames[0])
}
