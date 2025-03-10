package basic

import enc "github.com/named-data/ndnd/std/encoding"

// NameTrie is a simple implementation of a Name trie (node/subtree) used for PIT and FIB.
// It is slow due to the usage of TlvStr(). Subject to change when it explicitly affects performance.
type NameTrie[V any] struct {
	val V
	key string
	par *NameTrie[V]
	dep int
	chd map[string]*NameTrie[V]
}

// Value returns the value stored in the node.
func (n *NameTrie[V]) Value() V {
	return n.val
}

// SetValue puts some value in the node.
func (n *NameTrie[V]) SetValue(value V) {
	n.val = value
}

// ExactMatch returns the node that matches the name exactly. If no node matches, it returns nil.
func (n *NameTrie[V]) ExactMatch(name enc.Name) *NameTrie[V] {
	if len(name) <= n.dep {
		return n
	}
	c := name[n.dep].TlvStr()
	if ch, ok := n.chd[c]; ok {
		return ch.ExactMatch(name)
	} else {
		return nil
	}
}

// PrefixMatch returns the longest prefix match of the name.
// Always succeeds, but the returned node may be empty.
func (n *NameTrie[V]) PrefixMatch(name enc.Name) *NameTrie[V] {
	if len(name) <= n.dep {
		return n
	}
	c := name[n.dep].TlvStr()
	if ch, ok := n.chd[c]; ok {
		return ch.PrefixMatch(name)
	} else {
		return n
	}
}

// newTrieNode creates a new NameTrie node.
func newTrieNode[V any](key string, parent *NameTrie[V]) *NameTrie[V] {
	depth := 0
	if parent != nil {
		depth = parent.dep + 1
	}
	return &NameTrie[V]{
		par: parent,
		chd: map[string]*NameTrie[V]{},
		key: key,
		dep: depth,
	}
}

// MatchAlways finds or creates the node that matches the name exactly.
func (n *NameTrie[V]) MatchAlways(name enc.Name) *NameTrie[V] {
	if len(name) <= n.dep {
		return n
	}
	c := name[n.dep].TlvStr()
	ch, ok := n.chd[c]
	if !ok {
		ch = newTrieNode(c, n)
		n.chd[c] = ch
	}
	return ch.MatchAlways(name)
}

// FirstSatisfyOrNew finds or creates the first node along the path that satisfies the predicate.
func (n *NameTrie[V]) FirstSatisfyOrNew(name enc.Name, pred func(V) bool) *NameTrie[V] {
	if len(name) <= n.dep || pred(n.val) {
		return n
	}
	c := name[n.dep].TlvStr()
	ch, ok := n.chd[c]
	if !ok {
		ch = newTrieNode(c, n)
		n.chd[c] = ch
	}
	return ch.FirstSatisfyOrNew(name, pred)
}

// HasChildren returns whether the node has children.
func (n *NameTrie[V]) HasChildren() bool {
	return len(n.chd) > 0
}

// Prune deletes the node itself if no children.
// Automatically removes ancestors if empty.
func (n *NameTrie[V]) Prune() {
	n.PruneIf(func(V) bool { return true })
}

// PruneIf deletes the node and its ancestors if they are empty.
// Whether empty or not is defined by a given function.
func (n *NameTrie[V]) PruneIf(pred func(V) bool) {
	// Root node cannot be deleted.
	if n.par == nil {
		return
	}

	// Delete if no children and does not satisfy the predicate.
	if n.HasChildren() || !pred(n.val) {
		return
	}

	n.chd = nil // gc
	delete(n.par.chd, n.key)
	n.par.PruneIf(pred)
}

// Depth returns the depth of a node in the tree.
func (n *NameTrie[V]) Depth() int {
	return n.dep
}

// Parent returns its parent node.
func (n *NameTrie[V]) Parent() *NameTrie[V] {
	return n.par
}

// NewNameTrie creates a new NameTrie and returns the root node.
func NewNameTrie[V any]() *NameTrie[V] {
	return newTrieNode[V]("", nil)
}

// FirstNodeIf returns the first node that satisfies given condition, in DFS order.
func (n *NameTrie[V]) FirstNodeIf(pred func(V) bool) *NameTrie[V] {
	if pred(n.val) {
		return n
	}
	for _, c := range n.chd {
		if ret := c.FirstNodeIf(pred); ret != nil {
			return ret
		}
	}
	return nil
}
