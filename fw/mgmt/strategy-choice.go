/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/fw"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

// StrategyChoiceModule is the module that handles Strategy Choice Management.
type StrategyChoiceModule struct {
	manager                    *Thread
	nextStrategyDatasetVersion uint64
	strategyPrefix             enc.Name
}

func (s *StrategyChoiceModule) String() string {
	return "StrategyChoiceMgmt"
}

func (s *StrategyChoiceModule) registerManager(manager *Thread) {
	s.manager = manager
	s.strategyPrefix = make(enc.Name, len(s.manager.localPrefix)+1)
	copy(s.strategyPrefix, s.manager.localPrefix)
	s.strategyPrefix[len(s.manager.localPrefix)] = enc.Component{
		Typ: enc.TypeGenericNameComponent,
		Val: []byte("strategy"),
	}
}

func (s *StrategyChoiceModule) getManager() *Thread {
	return s.manager
}

func (s *StrategyChoiceModule) handleIncomingInterest(interest ndn.Interest, pitToken []byte, inFace uint64) {
	// Only allow from /localhost
	if !s.manager.localPrefix.IsPrefix(interest.Name()) {
		core.LogWarn(s, "Received strategy management Interest from non-local source - DROP")
		return
	}

	// Dispatch by verb
	verb := interest.Name()[s.manager.prefixLength()+1].String()
	switch verb {
	case "set":
		s.set(interest, pitToken, inFace)
	case "unset":
		s.unset(interest, pitToken, inFace)
	case "list":
		s.list(interest, pitToken, inFace)
	default:
		core.LogWarn(s, "Received Interest for non-existent verb '", verb, "'")
		response := makeControlResponse(501, "Unknown verb", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}
}

func (s *StrategyChoiceModule) set(interest ndn.Interest, pitToken []byte, inFace uint64) {
	var response *mgmt.ControlResponse

	if len(interest.Name()) < s.manager.prefixLength()+3 {
		// Name not long enough to contain ControlParameters
		core.LogWarn(s, "Missing ControlParameters in ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	params := decodeControlParameters(s, interest)
	if params == nil {
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	if params.Name == nil {
		core.LogWarn(s, "Missing Name in ControlParameters for ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	if params.Strategy == nil {
		core.LogWarn(s, "Missing Strategy in ControlParameters for ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	if !s.strategyPrefix.IsPrefix(params.Strategy.Name) {
		core.LogWarn(s, "Unknown Strategy=", params.Strategy.Name, " in ControlParameters for Interest=", interest.Name())
		response = makeControlResponse(404, "Unknown strategy", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	strategyName := params.Strategy.Name[len(s.strategyPrefix)].String()
	availableVersions, ok := fw.StrategyVersions[strategyName]
	if !ok {
		core.LogWarn(s, "Unknown Strategy=", params.Strategy, " in ControlParameters for Interest=", interest.Name())
		response = makeControlResponse(404, "Unknown strategy", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	// Add/verify version information for strategy
	strategyVersion := availableVersions[0]
	for _, version := range availableVersions {
		if version > strategyVersion {
			strategyVersion = version
		}
	}
	if len(params.Strategy.Name) > len(s.strategyPrefix)+1 &&
		params.Strategy.Name[len(s.strategyPrefix)+1].Typ != enc.TypeVersionNameComponent {
		core.LogWarn(s, "Unknown Version=", params.Strategy.Name[len(s.strategyPrefix)+1],
			" for Strategy=", params.Strategy, " in ControlParameters for Interest=", interest.Name())
		response = makeControlResponse(404, "Unknown strategy version", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	} else if len(params.Strategy.Name) > len(s.strategyPrefix)+1 {
		strategyVersionBytes := params.Strategy.Name[len(s.strategyPrefix)+1].Val
		strategyVersion, _, err := enc.ParseNat(strategyVersionBytes)
		if err != nil {
			core.LogWarn(s, "Unknown Version=", params.Strategy.Name[len(s.strategyPrefix)+1],
				" for Strategy=", params.Strategy, " in ControlParameters for Interest=", interest.Name())
			response = makeControlResponse(404, "Unknown strategy version", nil)
			s.manager.sendResponse(response, interest, pitToken, inFace)
			return
		}
		foundMatchingVersion := false
		for _, version := range availableVersions {
			if version == uint64(strategyVersion) {
				foundMatchingVersion = true
			}
		}
		if !foundMatchingVersion {
			core.LogWarn(s, "Unknown Version=", strategyVersion, " for Strategy=", params.Strategy,
				" in ControlParameters for Interest=", interest.Name())
			response = makeControlResponse(404, "Unknown strategy version", nil)
			s.manager.sendResponse(response, interest, pitToken, inFace)
			return
		}
	} else {
		// Add missing version information to strategy name
		params.Strategy.Name = append(params.Strategy.Name, enc.NewVersionComponent(strategyVersion))
	}
	table.FibStrategyTable.SetStrategyEnc(params.Name, params.Strategy.Name)

	core.LogInfo(s, "Set strategy for Name=", params.Name, " to Strategy=", params.Strategy)
	responseParams := map[string]any{}
	responseParams["Name"] = params.Name
	responseParams["Strategy"] = params.Strategy
	response = makeControlResponse(200, "OK", responseParams)
	s.manager.sendResponse(response, interest, pitToken, inFace)
}

func (s *StrategyChoiceModule) unset(interest ndn.Interest, pitToken []byte, inFace uint64) {
	var response *mgmt.ControlResponse

	if len(interest.Name()) < s.manager.prefixLength()+3 {
		// Name not long enough to contain ControlParameters
		core.LogWarn(s, "Missing ControlParameters in ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	params := decodeControlParameters(s, interest)
	if params == nil {
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	if params.Name == nil {
		core.LogWarn(s, "Missing Name in ControlParameters for ", interest.Name())
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}

	if len(params.Name) == 0 {
		core.LogWarn(s, "Cannot unset strategy for Name=", params.Name)
		response = makeControlResponse(400, "ControlParameters is incorrect", nil)
		s.manager.sendResponse(response, interest, pitToken, inFace)
		return
	}
	table.FibStrategyTable.UnSetStrategyEnc(params.Name)

	core.LogInfo(s, "Unset Strategy for Name=", params.Name)
	responseParams := map[string]any{}
	responseParams["Name"] = params.Name
	response = makeControlResponse(200, "OK", responseParams)
	s.manager.sendResponse(response, interest, pitToken, inFace)
}

func (s *StrategyChoiceModule) list(interest ndn.Interest, pitToken []byte, _ uint64) {
	if len(interest.Name()) > s.manager.prefixLength()+2 {
		// Ignore because contains version and/or segment components
		return
	}

	// Generate new dataset
	// TODO: For thread safety, we should lock the Strategy table from writes until we are done
	entries := table.FibStrategyTable.GetAllForwardingStrategies()
	strategyChoiceList := []*mgmt.StrategyChoice{}
	for _, fsEntry := range entries {
		strategyChoiceList = append(strategyChoiceList,
			&mgmt.StrategyChoice{Name: fsEntry.Name(), Strategy: &mgmt.Strategy{Name: fsEntry.GetStrategy()}})
	}
	strategyChoiceMsg := &mgmt.StrategyChoiceMsg{StrategyChoices: strategyChoiceList}
	wire := strategyChoiceMsg.Encode()
	name, _ := enc.NameFromStr(s.manager.localPrefix.String() + "/strategy-choice/list")
	segments := makeStatusDataset(name, s.nextStrategyDatasetVersion, wire)
	s.manager.transport.Send(segments, pitToken, nil)

	core.LogTrace(s, "Published strategy choice dataset version=", s.nextStrategyDatasetVersion,
		", containing ", len(segments), " segments")
	s.nextStrategyDatasetVersion++
}
