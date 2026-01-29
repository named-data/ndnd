package basic_test

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests the insertion, exact and prefix matching, and pruning behavior of a basic name‑trie data structure.
func TestBasicMatch(t *testing.T) {
	tu.SetT(t)

	var name enc.Name
	var n *basic_engine.NameTrie[int]
	trie := basic_engine.NewNameTrie[int]()

	// Empty match
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	require.True(t, nil == trie.ExactMatch(name))
	require.Equal(t, 0, trie.PrefixMatch(name).Depth())

	// Create /a/b
	name = tu.NoErr(enc.NameFromStr("/a/b"))
	n = trie.MatchAlways(name)
	require.Equal(t, 2, n.Depth())
	n.SetValue(10)
	require.Equal(t, 10, n.Value())
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	require.Equal(t, n, trie.PrefixMatch(name))
	require.True(t, nil == trie.ExactMatch(name))

	// First or new will not create /a/b/c
	hasValue := func(x int) bool {
		return x != 0
	}
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	n = trie.FirstSatisfyOrNew(name, hasValue)
	require.Equal(t, 2, n.Depth())

	// MatchAlways will create /a/b/c
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	n = trie.MatchAlways(name)
	require.Equal(t, 3, n.Depth())
	require.Equal(t, 10, n.Parent().Value())

	// Prefix match can reach /a for /a/c
	name = tu.NoErr(enc.NameFromStr("/a/c"))
	n = trie.PrefixMatch(name)
	require.Equal(t, 1, n.Depth())

	// First or new will create /a/c
	name = tu.NoErr(enc.NameFromStr("/a/c"))
	n = trie.FirstSatisfyOrNew(name, hasValue)
	require.Equal(t, 2, n.Depth())
	require.Equal(t, n, trie.ExactMatch(name))

	// Remove /a/b/c will remove /a/b but not /a/c
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	n = trie.ExactMatch(name)
	n.Prune()
	name = tu.NoErr(enc.NameFromStr("/a/b"))
	require.True(t, nil == trie.ExactMatch(name))
	require.Equal(t, 1, trie.PrefixMatch(name).Depth())

	// Remove /a/c will remove everything except the root
	name = tu.NoErr(enc.NameFromStr("/a/c"))
	n = trie.ExactMatch(name)
	n.Prune()
	require.False(t, trie.HasChildren())
}

// (AI GENERATED DESCRIPTION): PruneIf conditionally removes a NameTrie node and its entire subtree when the node’s value satisfies a given predicate and it has no other non‑zero children, updating parent links but preserving ancestors that still have remaining non‑zero descendants.
func TestPruneIf(t *testing.T) {
	tu.SetT(t)

	var name enc.Name
	var n *basic_engine.NameTrie[int]
	trie := basic_engine.NewNameTrie[int]()

	// /a/b - value
	name = tu.NoErr(enc.NameFromStr("/a/b"))
	ab := trie.MatchAlways(name)
	ab.SetValue(10)

	// /a/b/c - no value
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	abc := trie.MatchAlways(name)
	abc.SetValue(0)
	require.Equal(t, 3, abc.Depth())
	require.Equal(t, 10, abc.Parent().Value())

	// /a/b/d - no value
	name = tu.NoErr(enc.NameFromStr("/a/b/d"))
	abd := trie.MatchAlways(name)
	abd.SetValue(0)

	// /e/f/g - value
	name = tu.NoErr(enc.NameFromStr("/e/f/g"))
	efg := trie.MatchAlways(name)
	efg.SetValue(30)

	// zero is no value
	noValue := func(x int) bool { return x == 0 }

	// PruneIf /a/b/c will not remove /a/b
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	n = trie.ExactMatch(name)
	require.Equal(t, abc, n)
	n.PruneIf(noValue)
	require.Nil(t, trie.ExactMatch(name))
	name = tu.NoErr(enc.NameFromStr("/a/b"))
	require.Equal(t, ab, trie.ExactMatch(name))

	// Prune again with /a/b set to zero
	ab.SetValue(0)
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	abc = trie.MatchAlways(name)
	n = trie.ExactMatch(name)
	require.Equal(t, abc, n)
	n.PruneIf(noValue)
	require.Nil(t, trie.ExactMatch(name))

	// Make sure /a/b is not removed because it has other children
	name = tu.NoErr(enc.NameFromStr("/a/b"))
	require.Equal(t, ab, trie.ExactMatch(name))

	// Prune /a/b/d
	name = tu.NoErr(enc.NameFromStr("/a/b/d"))
	n = trie.ExactMatch(name)
	require.Equal(t, abd, n)
	n.PruneIf(noValue)
	require.Nil(t, trie.ExactMatch(name))

	// Make sure /a/b is now removed
	name = tu.NoErr(enc.NameFromStr("/a/b"))
	require.Nil(t, trie.ExactMatch(name))

	// /e/f/g is not removed
	name = tu.NoErr(enc.NameFromStr("/e/f/g"))
	require.Equal(t, efg, trie.ExactMatch(name))

	// Prune /e/f should do nothing
	name = tu.NoErr(enc.NameFromStr("/e/f"))
	n = trie.ExactMatch(name)
	n.PruneIf(noValue)
	name = tu.NoErr(enc.NameFromStr("/e/f/g"))
	require.Equal(t, efg, trie.ExactMatch(name))

	// Create /a/b/c = 10. Now PruneIf does nothing
	name = tu.NoErr(enc.NameFromStr("/a/b/c"))
	n = trie.MatchAlways(name)
	n.SetValue(10)
	n.PruneIf(noValue)
	require.Equal(t, n, trie.ExactMatch(name))
}
