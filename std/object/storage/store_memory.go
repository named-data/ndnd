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

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		root: &memoryStoreNode{},
	}
}

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

func (s *MemoryStore) Remove(name enc.Name) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.root.remove(name, false)
	return nil
}

func (s *MemoryStore) RemovePrefix(prefix enc.Name) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.root.remove(prefix, true)
	return nil
}

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

func (s *MemoryStore) Begin() (ndn.Store, error) {
	s.txMutex.Lock()
	s.tx = &memoryStoreNode{}
	return s, nil
}

func (s *MemoryStore) Commit() error {
	defer s.txMutex.Unlock()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.root.merge(s.tx)
	s.tx = nil
	return nil
}

func (s *MemoryStore) Rollback() error {
	defer s.txMutex.Unlock()
	s.tx = nil
	return nil
}

func (s *MemoryStore) MemSize() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	size := 0
	s.root.walk(func(n *memoryStoreNode) { size += len(n.wire) })
	return size
}

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

func (n *memoryStoreNode) walk(f func(*memoryStoreNode)) {
	f(n)
	for _, child := range n.children {
		child.walk(f)
	}
}
