/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import (
	"strconv"

	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
)

// Strategy represents a forwarding strategy.
type Strategy interface {
	Instantiate(fwThread *Thread)
	String() string
	GetName() enc.Name

	AfterContentStoreHit(
		packet *defn.Pkt,
		pitEntry table.PitEntry,
		inFace uint64)
	AfterReceiveData(
		packet *defn.Pkt,
		pitEntry table.PitEntry,
		inFace uint64)
	AfterReceiveInterest(
		packet *defn.Pkt,
		pitEntry table.PitEntry,
		inFace uint64,
		nexthops [defn.MaxNextHops]*table.FibNextHopEntry,
		nexthopsCount int,
	)
	BeforeSatisfyInterest(
		pitEntry table.PitEntry,
		inFace uint64)
}

// StrategyBase provides common helper methods for YaNFD forwarding strategies.
type StrategyBase struct {
	thread          *Thread
	threadID        int
	name            enc.Name
	strategyName    enc.Component
	version         uint64
	strategyLogName string
}

// NewStrategyBase is a helper that allows specific strategies to initialize the base.
func (s *StrategyBase) NewStrategyBase(
	fwThread *Thread,
	strategyName enc.Component,
	version uint64,
	strategyLogName string,
) {
	s.thread = fwThread
	s.threadID = s.thread.threadID
	s.strategyName = strategyName
	s.name = defn.STRATEGY_PREFIX.Append(strategyName, enc.NewVersionComponent(version))
	s.version = version
	s.strategyLogName = strategyLogName
}

func (s *StrategyBase) String() string {
	return s.strategyLogName + "-v" + strconv.FormatUint(s.version, 10) + "-Thread" + strconv.Itoa(s.threadID)
}

// GetName returns the name of strategy, including version information.
func (s *StrategyBase) GetName() enc.Name {
	return s.name
}

// SendInterest sends an Interest on the specified face.
func (s *StrategyBase) SendInterest(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	nexthop uint64,
	inFace uint64,
) bool {
	return s.thread.processOutgoingInterest(packet, pitEntry, nexthop, inFace)
}

// SendData sends a Data packet on the specified face.
func (s *StrategyBase) SendData(
	packet *defn.Pkt,
	pitEntry table.PitEntry,
	nexthop uint64,
	inFace uint64,
) {
	var pitToken []byte
	if inRecord, ok := pitEntry.InRecords()[nexthop]; ok {
		pitToken = inRecord.PitToken
		delete(pitEntry.InRecords(), nexthop)
	}
	s.thread.processOutgoingData(packet, nexthop, pitToken, inFace)
}
