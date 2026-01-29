/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package face

import (
	"github.com/named-data/ndnd/fw/core"
)

// NullLinkService is a link service that drops all packets.
type NullLinkService struct {
	linkServiceBase
}

// MakeNullLinkService makes a NullLinkService.
func MakeNullLinkService(transport transport) *NullLinkService {
	l := new(NullLinkService)
	l.makeLinkServiceBase()
	l.transport = transport
	l.transport.setLinkService(l)
	return l
}

// Run runs the NullLinkService.
func (l *NullLinkService) Run(initial []byte) {
	FaceTable.Add(l)
	go func() {
		l.transport.runReceive()
		FaceTable.Remove(l.transport.FaceID())
	}()
}

// (AI GENERATED DESCRIPTION): Drops any incoming frame received on a null link service, logging a debug message indicating the frame was discarded.
func (l *NullLinkService) handleIncomingFrame(frame []byte) {
	// Do nothing
	core.Log.Debug(l, "Received frame on null link service - DROP")
}
