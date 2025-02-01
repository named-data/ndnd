package sync

import enc "github.com/named-data/ndnd/std/encoding"

// SvsPub is the generic received data publication from SVS.
type SvsPub struct {
	// Publisher that produced the data.
	Publisher enc.Name
	// Content of the data publication.
	Content enc.Wire
	// Full name of the data.
	DataName enc.Name
	// Boot time of the publisher.
	BootTime uint64
	// Sequence number of the publisher.
	SeqNum uint64
}

// Bytes gets the bytes of the data publication.
//
// This will allocate a new byte slice and copy the content.
// Using Content directly is more efficient whenever possible.
func (p *SvsPub) Bytes() []byte {
	return p.Content.Join()
}
