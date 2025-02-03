package io

import (
	"bytes"
	"errors"
	"io"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/arc"
)

// BufT is a temporary buffer with an associated Arc.
// A receiver must either manage lifetime of the buffer or copy it.
type BufT struct {
	Buf []byte
	*arc.Arc[*bytes.Buffer]
}

// ReadTlvStream reads a stream of TLV-encoded packets from the given reader.
func ReadTlvStream(
	reader io.Reader,
	onFrame func(BufT) bool,
	ignoreError func(error) bool,
) error {
	bufArc, recvBuf := streamBuffer()
	defer func() { bufArc.Dec() }()

	recvOff := 0
	tlvOff := 0

	for {
		// If less than one packet space remains in buffer, shift to beginning
		if len(recvBuf)-recvOff < ndn.MaxNDNPacketSize {
			// Get a new buffer
			oldBufArc, oldRecvBuf := bufArc, recvBuf
			bufArc, recvBuf = streamBuffer()

			// Copy unparsed data to new buffer
			copy(recvBuf, oldRecvBuf[tlvOff:recvOff])
			recvOff -= tlvOff
			tlvOff = 0

			// Release old buffer
			oldBufArc.Dec()
		}

		// Read multiple packets at once
		readSize, err := reader.Read(recvBuf[recvOff:])
		recvOff += readSize
		if err != nil {
			if ignoreError != nil && ignoreError(err) {
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		// Determine whether valid packet received
		for {
			rdr := enc.NewBufferView(recvBuf[tlvOff:recvOff])

			typ, err := rdr.ReadTLNum()
			if err != nil {
				// Probably incomplete packet
				break
			}

			len, err := rdr.ReadTLNum()
			if err != nil {
				// Probably incomplete packet
				break
			}

			tlvSize := typ.EncodingLength() + len.EncodingLength() + int(len)

			if recvOff-tlvOff >= tlvSize {
				// Packet was successfully received, send up to link service
				shouldContinue := onFrame(BufT{recvBuf[tlvOff : tlvOff+tlvSize], bufArc})
				if !shouldContinue {
					return nil
				}
				tlvOff += tlvSize
			} else if recvOff-tlvOff > ndn.MaxNDNPacketSize {
				// Invalid packet, something went wrong
				return errors.New("received too much data without valid TLV block")
			} else {
				// Incomplete packet (for sure)
				break
			}
		}
	}
}
