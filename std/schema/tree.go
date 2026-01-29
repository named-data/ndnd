package schema

import (
	"errors"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
)

// Tree represents an NTSchema tree.
// It is supposed to be a static knowledge and shared by all parties in the system at compile time.
// The execution order: construct the tree -> apply policies & env setup -> attach to engine
type Tree struct {
	root *Node
	lock sync.RWMutex

	engine ndn.Engine
}

// (AI GENERATED DESCRIPTION): Returns the fixed string `"schema"` as the textual representation of a `Tree`.
func (t *Tree) String() string {
	return "schema"
}

// (AI GENERATED DESCRIPTION): Returns the ndn.Engine associated with this Tree.
func (t *Tree) Engine() ndn.Engine {
	return t.engine
}

// (AI GENERATED DESCRIPTION): Returns a pointer to the root node of the tree.
func (t *Tree) Root() *Node {
	return t.root
}

// Attach the tree to the engine at prefix
func (t *Tree) Attach(prefix enc.Name, engine ndn.Engine) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.root == nil {
		return errors.New("cannot attach an empty tree")
	}
	t.root.SetAttachedPrefix(prefix)
	path := make(enc.NamePattern, len(prefix))
	for i, c := range prefix {
		path[i] = c
	}
	err := t.root.OnAttach(path, engine)
	if err != nil {
		return err
	}
	err = engine.AttachHandler(prefix, t.intHandler)
	if err != nil {
		return err
	}
	log.Info(t, "Attached to engine")
	t.engine = engine
	return nil
}

// Detach the schema tree from the engine
func (t *Tree) Detach() {
	if t.engine == nil {
		return
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	log.Info(t, "Detached from engine")
	t.engine.DetachHandler(t.root.AttachedPrefix())
	t.root.OnDetach()
}

// Match an NDN name to a (variable) matching
func (t *Tree) Match(name enc.Name) *MatchedNode {
	return t.root.Match(name)
}

// intHandler is the callback called by the engine that handles an incoming Interest.
func (t *Tree) intHandler(args ndn.InterestHandlerArgs) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	matchName := args.Interest.Name()
	mNode := t.root.Match(matchName)
	if mNode == nil {
		log.Warn(t, "Unexpected Interest - DROP", "name", matchName)
		return
	}
	mNode.Node.OnInterest(args, mNode.Matching)
}

// At the path return the node. Path does not include the attached prefix.
func (t *Tree) At(path enc.NamePattern) *Node {
	return t.root.At(path)
}

// PutNode puts the specified node at the specified path. Path does not include the attached prefix.
func (t *Tree) PutNode(path enc.NamePattern, desc *NodeImplDesc) *Node {
	t.lock.Lock()
	defer t.lock.Unlock()

	if len(path) == 0 {
		if t.root == nil {
			t.root = &Node{}
			t.root.desc = desc
			t.root.impl = desc.Create(t.root)
			return t.root
		} else {
			panic("schema node already exists")
		}
	} else {
		if t.root == nil {
			t.root = &Node{}
			t.root.desc = BaseNodeDesc
			t.root.impl = CreateBaseNode(t.root)
		}
		return t.root.PutNode(path, desc)
	}
}

// RLock locks the tree for read use
func (t *Tree) RLock() {
	t.lock.RLock()
}

// RUnlock unlocks the tree locked by RLock
func (t *Tree) RUnlock() {
	t.lock.RUnlock()
}
