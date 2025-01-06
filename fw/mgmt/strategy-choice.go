/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/fw"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// StrategyChoiceModule is the module that handles Strategy Choice Management.
type StrategyChoiceModule struct {
	manager *Thread
}

func (s *StrategyChoiceModule) String() string {
	return "StrategyChoiceMgmt"
}

func (s *StrategyChoiceModule) registerManager(manager *Thread) {
	s.manager = manager
}

func (s *StrategyChoiceModule) getManager() *Thread {
	return s.manager
}

func (s *StrategyChoiceModule) handleIncomingInterest(interest *Interest) {
	// Only allow from /localhost
	if !LOCAL_PREFIX.IsPrefix(interest.Name()) {
		core.LogWarn(s, "Received strategy management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[len(LOCAL_PREFIX)+1].String()
	switch verb {
	case "set":
		s.set(interest)
	case "unset":
		s.unset(interest)
	case "list":
		s.list(interest)
	default:
		s.manager.sendCtrlResp(interest, 501, "Unknown verb", nil)
		return
	}
}

func (s *StrategyChoiceModule) set(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(s, interest)
	if params == nil {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}

	if params.Strategy == nil {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Strategy)", nil)
		return
	}

	if !defn.STRATEGY_PREFIX.IsPrefix(params.Strategy.Name) {
		core.LogWarn(s, "Invalid Strategy=", params.Strategy.Name)
		s.manager.sendCtrlResp(interest, 404, "Invalid strategy", nil)
		return
	}

	strategyName := params.Strategy.Name[len(defn.STRATEGY_PREFIX)].String()
	availableVersions, ok := fw.StrategyVersions[strategyName]
	if !ok {
		core.LogWarn(s, "Unknown Strategy=", params.Strategy)
		s.manager.sendCtrlResp(interest, 404, "Unknown strategy", nil)
		return
	}

	// Add/verify version information for strategy
	strategyVersion := availableVersions[0]
	for _, version := range availableVersions {
		if version > strategyVersion {
			strategyVersion = version
		}
	}
	if len(params.Strategy.Name) > len(defn.STRATEGY_PREFIX)+1 && params.Strategy.Name[len(defn.STRATEGY_PREFIX)+1].Typ != enc.TypeVersionNameComponent {
		core.LogWarn(s, "Invalid Version=", params.Strategy.Name[len(defn.STRATEGY_PREFIX)+1], " for Strategy=", params.Strategy)
		s.manager.sendCtrlResp(interest, 404, "Unknown strategy version", nil)
		return
	} else if len(params.Strategy.Name) > len(defn.STRATEGY_PREFIX)+1 {
		strategyVersionBytes := params.Strategy.Name[len(defn.STRATEGY_PREFIX)+1].Val
		strategyVersion, _, err := enc.ParseNat(strategyVersionBytes)
		if err != nil {
			core.LogWarn(s, "Invalid Version=", params.Strategy.Name[len(defn.STRATEGY_PREFIX)+1], " for Strategy=", params.Strategy)
			s.manager.sendCtrlResp(interest, 404, "Invalid strategy version", nil)
			return
		}
		foundMatchingVersion := false
		for _, version := range availableVersions {
			if version == uint64(strategyVersion) {
				foundMatchingVersion = true
			}
		}
		if !foundMatchingVersion {
			core.LogWarn(s, "Unknown Version=", strategyVersion, " for Strategy=", params.Strategy)
			s.manager.sendCtrlResp(interest, 404, "Unknown strategy version", nil)
			return
		}
	} else {
		// Add missing version information to strategy name
		params.Strategy.Name = params.Strategy.Name.Append(enc.NewVersionComponent(strategyVersion))
	}
	table.FibStrategyTable.SetStrategyEnc(params.Name, params.Strategy.Name)

	s.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{
		Name:     params.Name,
		Strategy: params.Strategy,
	})

	core.LogInfo(s, "Set strategy for Name=", params.Name, " to Strategy=", params.Strategy.Name)
}

func (s *StrategyChoiceModule) unset(interest *Interest) {
	if len(interest.Name()) < len(LOCAL_PREFIX)+3 {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	params := decodeControlParameters(s, interest)
	if params == nil {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect", nil)
		return
	}

	if params.Name == nil {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (missing Name)", nil)
		return
	}

	if len(params.Name) == 0 {
		s.manager.sendCtrlResp(interest, 400, "ControlParameters is incorrect (empty Name)", nil)
		return
	}

	table.FibStrategyTable.UnSetStrategyEnc(params.Name)
	core.LogInfo(s, "Unset Strategy for Name=", params.Name)

	s.manager.sendCtrlResp(interest, 200, "OK", &mgmt.ControlArgs{Name: params.Name})
}

func (s *StrategyChoiceModule) list(interest *Interest) {
	if len(interest.Name()) > len(LOCAL_PREFIX)+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	// TODO: For thread safety, we should lock the Strategy table from writes until we are done
	entries := table.FibStrategyTable.GetAllForwardingStrategies()
	choices := []*mgmt.StrategyChoice{}
	for _, fsEntry := range entries {
		choices = append(choices, &mgmt.StrategyChoice{
			Name:     fsEntry.Name(),
			Strategy: &mgmt.Strategy{Name: fsEntry.GetStrategy()},
		})
	}
	dataset := &mgmt.StrategyChoiceMsg{StrategyChoices: choices}

	name := LOCAL_PREFIX.Append(
		enc.NewStringComponent(enc.TypeGenericNameComponent, "strategy-choice"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "list"),
	)
	s.manager.sendStatusDataset(interest, name, dataset.Encode())
}
