/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package defn

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// Pkt represents a pending packet to be sent or recently
// received on the link, plus any associated metadata.
type Pkt struct {
	Name enc.Name
	L3   *FwPacket
	Raw  enc.Wire

	PitToken       []byte
	CongestionMark optional.Optional[uint64]

	IncomingFaceID uint64
	NextHopFaceID  optional.Optional[uint64]
	EgressRouter   enc.Name
	Bier           []byte
}
