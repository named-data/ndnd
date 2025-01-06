package defn

import enc "github.com/named-data/ndnd/std/encoding"

// Localhost prefix for NFD
var LOCAL_PREFIX = enc.Name{enc.LOCALHOST, enc.NewStringComponent(enc.TypeGenericNameComponent, "nfd")}

// Non-local prefix for NFD
var NON_LOCAL_PREFIX = enc.Name{enc.LOCALHOP, enc.NewStringComponent(enc.TypeGenericNameComponent, "nfd")}

// Prefix for all stratgies
var STRATEGY_PREFIX = LOCAL_PREFIX.Append(enc.NewStringComponent(enc.TypeGenericNameComponent, "strategy"))

// Default forwarding strategy name
var DEFAULT_STRATEGY = STRATEGY_PREFIX.Append(
	enc.NewStringComponent(enc.TypeGenericNameComponent, "best-route"),
	enc.NewVersionComponent(1))
