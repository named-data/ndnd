/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package fw

import (
	"github.com/named-data/ndnd/fw/core"
)

var strategyTypes []func() Strategy

// StrategyVersions contains a list of strategies mapping to a list of their versions
var StrategyVersions = make(map[string][]uint64)

// InstantiateStrategies instantiates all strategies for a forwarding thread.
func InstantiateStrategies(fwThread *Thread) map[uint64]Strategy {
	strategies := make(map[uint64]Strategy, len(strategyTypes))

	for _, strategyType := range strategyTypes {
		strategy := strategyType()
		strategy.Instantiate(fwThread)
		strategyName := strategy.GetName()
		strategies[strategyName.Hash()] = strategy
		core.LogDebug("StrategyLoader", "Instantiated Strategy=", strategy.GetName(), " for Thread=", fwThread.GetID())
	}

	return strategies
}
