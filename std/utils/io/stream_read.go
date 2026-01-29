package io

import (
	"errors"
	"fmt"
	"io"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// (AI GENERATED DESCRIPTION): Continuously reads TLV‑encoded packets from an io.Reader, buffering partial data and invoking a callback for each complete frame while handling errors and optional early termination.
func ReadTlvStream(
	reader io.Reader,
	onFrame func([]byte) bool,
	ignoreError func(error) bool,
) error {
	recvBuf := make([]byte, ndn.MaxNDNPacketSize*8)
	recvOff := 0
	tlvOff := 0

	for {
		// If less than one packet space remains in buffer, shift to beginning
		if len(recvBuf)-recvOff < ndn.MaxNDNPacketSize {
			copy(recvBuf, recvBuf[tlvOff:recvOff])
			recvOff -= tlvOff
			tlvOff = 0
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
				shouldContinue := onFrame(recvBuf[tlvOff : tlvOff+tlvSize])
				if !shouldContinue {
					return nil
				}
				tlvOff += tlvSize
			} else if recvOff-tlvOff > ndn.MaxNDNPacketSize {
				// Invalid packet, something went wrong
				return fmt.Errorf("received too much data without valid TLV block")
			} else {
				// Incomplete packet (for sure)
				break
			}
		}
	}
}
