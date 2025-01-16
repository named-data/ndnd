/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package dispatch

import (
	"sync"

	"github.com/named-data/ndnd/fw/defn"
)

// Face provides an interface that faces can satisfy (to avoid circular dependency between faces and forwarding)
type Face interface {
	String() string
	SetFaceID(faceID uint64)

	FaceID() uint64
	LocalURI() *defn.URI
	RemoteURI() *defn.URI
	Scope() defn.Scope
	LinkType() defn.LinkType
	MTU() int

	State() defn.State

	SendPacket(out OutPkt)
}

type OutPkt struct {
	Pkt      *defn.Pkt
	PitToken []byte
	InFace   uint64
}

// FaceDispatch is used to allow forwarding to interact with faces without a circular dependency issue.
var FaceDispatch sync.Map

// AddFace adds the specified face to the dispatch list.
func AddFace(id uint64, face Face) {
	FaceDispatch.Store(id, face)
}

// GetFace returns the specified face or nil if it does not exist.
func GetFace(id uint64) Face {
	face, ok := FaceDispatch.Load(id)
	if !ok {
		return nil
	}
	return face.(Face)
}

// RemoveFace removes the specified face from the dispatch map.
func RemoveFace(id uint64) {
	FaceDispatch.Delete(id)
}
