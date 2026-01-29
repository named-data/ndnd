package storage

import (
	"fmt"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

type MemoryStore struct {
	// root of the store
	root *memoryStoreNode
	// thread safety
	mutex sync.RWMutex

	// active transaction
	tx *memoryStoreNode
	// transaction mutex
	txMutex sync.Mutex
}

type memoryStoreNode struct {
	// name component
	comp enc.Component
	// children
	children map[string]*memoryStoreNode
	// data wire
	wire []byte
}

// (AI GENERATED DESCRIPTION): Creates a new MemoryStore instance initialized with an empty root node.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		root: &memoryStoreNode{},
	}
}

// (AI GENERATED DESCRIPTION): Retrieves the wire‑bytes for the packet named `name`; if `prefix` is true and the exact node has no stored data, it returns the newest descendant packet instead.
func (s *MemoryStore) Get(name enc.Name, prefix bool) ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if node := s.root.find(name); node != nil {
		if node.wire == nil && prefix {
			node = node.findNewest()
		}
		return node.wire, nil
	}
	return nil, nil
}

// (AI GENERATED DESCRIPTION): Stores the given wire‑encoded data under the specified name in the memory store, using the active transaction if one exists, while protecting the operation with a mutex lock.
func (s *MemoryStore) Put(name enc.Name, wire []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	root := s.root
	if s.tx != nil {
		root = s.tx
	}

	root.insert(name, wire)
	return nil
}

// (AI GENERATED DESCRIPTION): Removes the entry identified by the given name from the in‑memory store.
func (s *MemoryStore) Remove(name enc.Name) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.root.remove(name, false)
	return nil
}

// (AI GENERATED DESCRIPTION): Removes all entries from the memory store whose names begin with the specified prefix.
func (s *MemoryStore) RemovePrefix(prefix enc.Name) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.root.remove(prefix, true)
	return nil
}

// (AI GENERATED DESCRIPTION): Removes all immediate (flat) child entries of the given prefix whose component keys fall within the inclusive range from `first` to `last`.
func (s *MemoryStore) RemoveFlatRange(prefix enc.Name, first enc.Component, last enc.Component) error {
	firstKey, lastKey := first.TlvStr(), last.TlvStr()
	if firstKey > lastKey {
		return fmt.Errorf("firstKey > lastKey")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	pfx := s.root.find(prefix)
	for child := range pfx.children {
		if child >= firstKey && child <= lastKey {
			delete(pfx.children, child)
		}
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Begins a transaction on the MemoryStore by initializing a transaction node and locking the transaction mutex.
func (s *MemoryStore) Begin() (ndn.Store, error) {
	s.txMutex.Lock()
	s.tx = &memoryStoreNode{}
	return s, nil
}

// (AI GENERATED DESCRIPTION): Commits the pending transaction by merging its changes into the root store and clearing the transaction buffer.
func (s *MemoryStore) Commit() error {
	defer s.txMutex.Unlock()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.root.merge(s.tx)
	s.tx = nil
	return nil
}

// (AI GENERATED DESCRIPTION): Reverts any active transaction by clearing the transaction state and releasing the transaction mutex.
func (s *MemoryStore) Rollback() error {
	defer s.txMutex.Unlock()
	s.tx = nil
	return nil
}

// (AI GENERATED DESCRIPTION): Returns the total number of bytes used by all packets stored in the MemoryStore by summing the lengths of their wire-encoded representations.
func (s *MemoryStore) MemSize() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	size := 0
	s.root.walk(func(n *memoryStoreNode) { size += len(n.wire) })
	return size
}

// (AI GENERATED DESCRIPTION): Finds and returns the memoryStoreNode that matches the given name path in the tree, or nil if no such node exists.
func (n *memoryStoreNode) find(name enc.Name) *memoryStoreNode {
	if len(name) == 0 {
		return n
	}

	if n.children == nil {
		return nil
	}

	key := name[0].TlvStr()
	if child := n.children[key]; child != nil {
		return child.find(name[1:])
	} else {
		return nil
	}
}

// (AI GENERATED DESCRIPTION): Finds and returns the leaf node whose name is the lexicographically greatest among the children of this node (or its descendants), or `nil` if no children exist.
func (n *memoryStoreNode) findNewest() *memoryStoreNode {
	if len(n.children) == 0 {
		return n
	}

	var newest string = ""
	for key := range n.children {
		if key > newest {
			newest = key
		}
	}
	if newest == "" {
		return nil
	}

	known := n.children[newest]
	if sub := known.findNewest(); sub != nil {
		return sub
	}
	return known
}

// (AI GENERATED DESCRIPTION): Recursively inserts a wire representation into a memory‑based name tree, creating child nodes for each name component and storing the wire at the leaf node.
func (n *memoryStoreNode) insert(name enc.Name, wire []byte) {
	if len(name) == 0 {
		n.wire = wire
		return
	}

	if n.children == nil {
		n.children = make(map[string]*memoryStoreNode)
	}

	key := name[0].TlvStr()
	if child := n.children[key]; child != nil {
		child.insert(name[1:], wire)
	} else {
		child = &memoryStoreNode{comp: name[0]}
		child.insert(name[1:], wire)
		n.children[key] = child
	}
}

// (AI GENERATED DESCRIPTION): Recursively removes the entry for a given name from the in‑memory tree, optionally pruning all descendant nodes, and returns a flag indicating whether the caller should delete this node.
func (n *memoryStoreNode) remove(name enc.Name, prefix bool) bool {
	// return value is if the parent should prune this child
	if len(name) == 0 {
		n.wire = nil
		if prefix {
			n.children = nil // prune subtree
		}
		return n.children == nil
	}

	if n.children == nil {
		return false
	}

	key := name[0].TlvStr()
	if child := n.children[key]; child != nil {
		prune := child.remove(name[1:], prefix)
		if prune {
			delete(n.children, key)
		}
	}

	return n.wire == nil && len(n.children) == 0
}

// (AI GENERATED DESCRIPTION): Merges a transaction memoryStoreNode into the current node, copying its wire data and recursively merging or inserting any child nodes.
func (n *memoryStoreNode) merge(tx *memoryStoreNode) {
	if tx.wire != nil {
		n.wire = tx.wire
	}

	for key, child := range tx.children {
		if n.children == nil {
			n.children = make(map[string]*memoryStoreNode)
		}

		if nchild := n.children[key]; nchild != nil {
			nchild.merge(child)
		} else {
			n.children[key] = child
		}
	}
}

// (AI GENERATED DESCRIPTION): Recursively traverses the memory store tree in pre‑order, applying the supplied function to each node.
func (n *memoryStoreNode) walk(f func(*memoryStoreNode)) {
	f(n)
	for _, child := range n.children {
		child.walk(f)
	}
}
