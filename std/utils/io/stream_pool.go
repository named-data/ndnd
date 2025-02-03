package io

import (
	"bytes"
	"fmt"

	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/arc"
)

var count = 1

// streamBufferPool is the pool of buffers used for reading streams.
// When passed an Arc, downstreams must either increment it or copy the buffer.
var streamBufferPool = arc.NewArcPool(
	func() *bytes.Buffer {
		count++
		if count%100 == 0 {
			fmt.Println("StreamBufferPool: creating new buffer", count)
		}
		return &bytes.Buffer{}
	},
	func(buf *bytes.Buffer) {
		buf.Reset()
		buf.Grow(8 * ndn.MaxNDNPacketSize)
	})

// streamBuffer returns a buffer from the pool.
func streamBuffer() (*arc.Arc[*bytes.Buffer], []byte) {
	bufArc := streamBufferPool.Get()
	bufArc.Inc()
	recvBuf := bufArc.Load().AvailableBuffer()
	recvBuf = recvBuf[:cap(recvBuf)]
	return bufArc, recvBuf
}
