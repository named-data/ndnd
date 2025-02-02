package io

import (
	"errors"
	"io"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

func ReadTlvStream(
	reader io.Reader,
	onFrame func([]byte) bool,
	ignoreError func(error) bool,
) error {
	recvBuf := make([]byte, ndn.MaxNDNPacketSize*32)
	recvOff := 0
	tlvOff := 0

	for {
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
			rdr := enc.NewFastBufReader(recvBuf[tlvOff:recvOff])

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
				return errors.New("received too much data without valid TLV block")
			} else {
				// Incomplete packet (for sure)
				break
			}
		}

		// If less than one packet space remains in buffer, shift to beginning
		if recvOff-tlvOff < ndn.MaxNDNPacketSize {
			copy(recvBuf, recvBuf[tlvOff:recvOff])
			recvOff -= tlvOff
			tlvOff = 0
		}
	}
}
