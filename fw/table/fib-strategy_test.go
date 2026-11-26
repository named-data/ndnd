package table

import (
	"testing"

	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/stretchr/testify/assert"
)

// (AI GENERATED DESCRIPTION): Tests that the baseFibStrategyEntry getters return the correct name, strategy, and next hop list.
func TestFibStrategyEntryGetters(t *testing.T) {
	name, _ := enc.NameFromStr("/something")

	nextHop1 := FibNextHopEntry{
		Nexthop: 100,
		Cost:    101,
	}

	nextHop2 := FibNextHopEntry{
		Nexthop: 102,
		Cost:    103,
	}

	nextHops := []*FibNextHopEntry{&nextHop1, &nextHop2}

	bfse := baseFibStrategyEntry{
		component: name[0],
		name:      name,
		nexthops:  nextHops,
		strategy:  name,
	}

	assert.True(t, bfse.Name().Equal(name))
	assert.True(t, bfse.GetStrategy().Equal(name))
	assert.Equal(t, 2, len(bfse.GetNextHops()))
}

// (AI GENERATED DESCRIPTION): Tests that the combined nexthop/strategy lookups agree with FindNextHopsEnc and FindStrategyEnc for both FIB implementations.
func TestFindNextHopsAndStrategy(t *testing.T) {
	for _, algo := range []string{"nametree", "hashtable"} {
		t.Run(algo, func(t *testing.T) {
			if algo == "nametree" {
				newFibStrategyTableTree()
			} else {
				newFibStrategyTableHashTable(2)
			}
			fib := FibStrategyTable

			mk := func(s string) enc.Name { n, _ := enc.NameFromStr(s); return n }
			multicast := mk("/localhost/nfd/strategy/multicast/v=1")

			fib.InsertNextHopEnc(mk("/a"), 1, 10)
			fib.InsertNextHopEnc(mk("/a"), 2, 20)
			fib.InsertNextHopEnc(mk("/a/b/c/d"), 3, 10)
			fib.SetStrategyEnc(mk("/a/b"), multicast)

			var buf []*FibNextHopEntry
			for _, name := range []string{"/", "/x", "/a", "/a/b", "/a/b/c", "/a/b/c/d", "/a/b/c/d/e/f", "/a/x/y/z"} {
				n := mk(name)
				nexthops, strategyHash := fib.FindNextHopsAndStrategyEnc(n, buf)
				buf = nexthops

				assert.ElementsMatch(t, fib.FindNextHopsEnc(n), nexthops, name)
				assert.Equal(t, fib.FindStrategyEnc(n).Hash(), strategyHash, name)
				assert.Equal(t, strategyHash, fib.FindStrategyHashEnc(n), name)
			}

			// Unset strategy falls back to the default
			fib.UnSetStrategyEnc(mk("/a/b"))
			_, strategyHash := fib.FindNextHopsAndStrategyEnc(mk("/a/b/c"), nil)
			assert.Equal(t, defn.DEFAULT_STRATEGY.Hash(), strategyHash)
		})
	}
}
