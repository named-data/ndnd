package schema

import (
	"errors"
	"reflect"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
)

// Node is the class for a NTSchema node, the container of NodeImpl.
// TODO: Inheritance from BaseNode is really a bad model of this thing
// but I cannot come up with a better one in limited time.
// If possible, a mixin programming model may be better.
// TODO: (updated) a better choice may be separate the tree node (that handles Child, Parent, etc.)
// and the polymorphic functional part (than handles Get, Set, Events, etc.)
// For WASM use in the future, we may need a list of properties.
// Also, add ENV for Init.
type Node struct {
	// Impl is the pointer pointing to NodeImpl.
	impl NodeImpl

	// Chd holds all children.
	// Since a schema tree typically only has <10 branches, an array should not hurt performance.
	// Change when there found evidences showing this is the bottleneck.
	chd []*Node

	dep  uint
	par  *Node
	edge enc.ComponentPattern
	path enc.NamePattern
	desc *NodeImplDesc

	attachedPrefix enc.Name

	engine ndn.Engine
}

// (AI GENERATED DESCRIPTION): Returns the string representation of the node’s path.
func (n *Node) String() string {
	return n.path.String()
}

// Children of the node
func (n *Node) Children() []*Node {
	return n.chd
}

// Child of given edge
func (n *Node) Child(edge enc.ComponentPattern) *Node {
	for _, c := range n.chd {
		if c.UpEdge().Equal(edge) {
			return c
		}
	}
	return nil
}

// Parent of this node
func (n *Node) Parent() *Node {
	return n.par
}

// UpEdge is the edge value from its parent to itself
func (n *Node) UpEdge() enc.ComponentPattern {
	return n.edge
}

// Depth of the node in the tree.
// It includes the attached prefix, so the root node may have a positive depth
// For example, if the root is attached at prefix /ndn, then the child of path /<id> from the root
// will have a depth=2.
func (n *Node) Depth() uint {
	return n.dep
}

// Impl returns the actual functional part of the node
func (n *Node) Impl() NodeImpl {
	return n.impl
}

// Match an NDN name to a (variable) matching
// For example, /ndn/aa may match to a node at /ndn/<id> with matching <id> = "aa"
func (n *Node) Match(name enc.Name) *MatchedNode {
	if n.engine == nil {
		panic("called Node.Match() before attaching to an engine")
	}
	subName := name
	if len(n.attachedPrefix) > 0 {
		// Only happens when n is the root node
		if !n.attachedPrefix.IsPrefix(subName) {
			return nil
		}
		subName = subName[n.dep:]
	}
	match := make(enc.Matching)
	node := n.ContinueMatch(subName, match)
	if node == nil {
		return nil
	} else {
		return &MatchedNode{
			Node:     node,
			Name:     name,
			Matching: match,
		}
	}
}

// ContinueMatch is a sub-function used by Match
func (n *Node) ContinueMatch(remainingName enc.Name, curMatching enc.Matching) *Node {
	if len(remainingName) > 0 && remainingName[0].Typ == enc.TypeParametersSha256DigestComponent {
		curMatching[enc.ParamShaNameConvention] = remainingName[0].Val
		remainingName = remainingName[1:]
	}
	if len(remainingName) > 0 && remainingName[0].Typ == enc.TypeImplicitSha256DigestComponent {
		curMatching[enc.DigestShaNameConvention] = remainingName[0].Val
		remainingName = remainingName[1:]
	}
	if len(remainingName) <= 0 {
		return n
	}
	for _, c := range n.chd {
		if c.UpEdge().IsMatch(remainingName[0]) {
			c.UpEdge().Match(remainingName[0], curMatching)
			return c.ContinueMatch(remainingName[1:], curMatching)
		}
	}
	return nil
}

// RootNode returns the root node in a tree
func (n *Node) RootNode() *Node {
	if n.par == nil {
		return n
	} else {
		return n.par.RootNode()
	}
}

// Apply a (variable) matching and obtain the corresponding NDN name
// For example, apply {"id":[]byte{"aa"}} to a node at /ndn/<id> will get /ndn/aa
// Will attach "params-sha256" and "sha256digest" to the end of the name if exists.
func (n *Node) Apply(matching enc.Matching) *MatchedNode {
	if n.engine == nil {
		panic("called Node.Apply() before attaching to an engine")
	}
	nameLen := n.dep
	var paramSha, digestSha []byte
	if paramSha = matching[enc.ParamShaNameConvention]; paramSha != nil {
		nameLen += 1
	}
	if digestSha = matching[enc.DigestShaNameConvention]; digestSha != nil {
		nameLen += 1
	}
	ret := make(enc.Name, n.dep, nameLen)
	if n.ConstructName(matching, ret) == nil {
		if paramSha != nil {
			ret = append(ret, enc.Component{Typ: enc.TypeParametersSha256DigestComponent, Val: paramSha})
		}
		if digestSha != nil {
			ret = append(ret, enc.Component{Typ: enc.TypeImplicitSha256DigestComponent, Val: digestSha})
		}
		return &MatchedNode{
			Node:     n,
			Name:     ret,
			Matching: matching,
		}
	} else {
		return nil
	}
}

// ConstructName is the aux function used by Apply
func (n *Node) ConstructName(matching enc.Matching, ret enc.Name) error {
	if n.par == nil {
		if len(ret) < int(n.dep) {
			return errors.New("insufficient name length") // This error won't be returned to the user
		}
		copy(ret[:n.dep], n.attachedPrefix)
		return nil
	} else {
		c, err := n.edge.FromMatching(matching)
		if err != nil {
			return err
		}
		ret[n.dep-1] = *c
		return n.par.ConstructName(matching, ret)
	}
}

// OnInterest is the function called when an Interest comes.
// A base node shouldn't receive any Interest, so drops it.
func (n *Node) OnInterest(args ndn.InterestHandlerArgs, matching enc.Matching) {
	if n.impl == nil {
		log.Warn(n, "Unexpected Interest. Drop.", "name", args.Interest.Name())
	} else {
		n.impl.OnInterest(args, matching)
	}
}

// OnAttach is called when the node is attached to an engine
// Node will call the event set by policy
func (n *Node) OnAttach(path enc.NamePattern, engine ndn.Engine) error {
	n.engine = engine
	n.dep = uint(len(path))
	n.path = make(enc.NamePattern, len(path))
	copy(n.path, path)

	for _, c := range n.chd {
		nxtPath := append(path, c.UpEdge())
		err := c.OnAttach(nxtPath, engine)
		if err != nil {
			return err
		}
	}

	// Some nodes' attach event will assume its children is ready
	// So we call this after children's onAttach
	if n.impl != nil {
		n.impl.OnAttach()
	}

	return nil
}

// OnDetach is called when the node is detached from an engine
// BaseNode will call the event set by policy
func (n *Node) OnDetach() {
	if n.impl != nil {
		n.impl.OnDetach()
	}
	for _, c := range n.chd {
		c.OnDetach()
	}
	n.engine = nil
}

// Get a property or callback event
func (n *Node) Get(propName PropKey) any {
	return n.desc.Properties[propName].Get(n.impl)
}

// Set a property. Use Get() to update callback events.
func (n *Node) Set(propName PropKey, value any) error {
	return n.desc.Properties[propName].Set(n.impl, value)
}

// GetEvent returns an event with a given event name. Return nil if not exists.
func (n *Node) GetEvent(eventName PropKey) *EventTarget {
	defer func() { recover() }()
	val := reflect.ValueOf(n.impl).Elem()
	target := val.FieldByName(string(eventName)).Interface().(*EventTarget)
	return target
}

// AddEventListener adds `callback` to the event `eventName`
// Note that callback is a function pointer (so it's comparable)
func (n *Node) AddEventListener(eventName PropKey, callback *Callback) {
	n.GetEvent(eventName).Add(callback)
}

// RemoveEventListener removes `callback` from the event `eventName`
// Note that callback is a function pointer (so it's comparable)
func (n *Node) RemoveEventListener(eventName PropKey, callback *Callback) {
	n.GetEvent(eventName).Remove(callback)
}

// At gets a node/subtree at a given pattern path. The path does not include the attached prefix.
func (n *Node) At(path enc.NamePattern) *Node {
	if len(path) <= 0 {
		return n
	}
	for _, c := range n.chd {
		if c.UpEdge().Equal(path[0]) {
			return c.At(path[1:])
		}
	}
	return nil
}

// Engine returns the engine attached
func (n *Node) Engine() ndn.Engine {
	return n.engine
}

// PutNode creates a node/subtree at a given pattern path. The path does not include the attached prefix.
// Returns the new node.
func (n *Node) PutNode(path enc.NamePattern, desc *NodeImplDesc) *Node {
	if len(path) <= 0 {
		panic("schema node already exists")
	}
	for _, c := range n.chd {
		if c.UpEdge().Equal(path[0]) {
			return c.PutNode(path[1:], desc)
		}
	}
	nxtChd := &Node{
		dep:  0,
		par:  n,
		edge: path[0],
		desc: nil,
	}
	if len(path) > 1 {
		// In this case, node is not our direct child
		nxtChd.desc = BaseNodeDesc
		nxtChd.impl = CreateBaseNode(nxtChd)
		n.chd = append(n.chd, nxtChd)
		return nxtChd.PutNode(path[1:], desc)
	} else {
		nxtChd.desc = desc
		nxtChd.impl = desc.Create(nxtChd)
		n.chd = append(n.chd, nxtChd)
		return nxtChd
	}
}

// AttachedPrefix of the root node. Must be nil for all other nodes and before Attach.
func (n *Node) AttachedPrefix() enc.Name {
	return n.attachedPrefix
}

// SetAttachedPrefix sets the attached prefix of the root node.
func (n *Node) SetAttachedPrefix(prefix enc.Name) {
	if n.par == nil {
		n.attachedPrefix = prefix
	} else {
		panic("only root nodes are attachable")
	}
}

// BaseNodeImpl is the default implementation of NodeImpl
type BaseNodeImpl struct {
	Node        *Node
	OnAttachEvt *EventTarget
	OnDetachEvt *EventTarget
}

// (AI GENERATED DESCRIPTION): Returns the underlying node implementation as a NodeImpl interface.
func (n *BaseNodeImpl) NodeImplTrait() NodeImpl {
	return n
}

// OnInterest is the callback function when there is an incoming Interest.
func (n *BaseNodeImpl) OnInterest(args ndn.InterestHandlerArgs, matching enc.Matching) {
	log.Warn(n.Node, "Unexpected Interest. Drop.", "name", args.Interest.Name())
}

// OnAttach is called when the node is attached to an engine
func (n *BaseNodeImpl) OnAttach() error {
	event := &Event{
		TargetNode: n.Node,
		Target:     nil,
	}
	ret := n.OnAttachEvt.DispatchUntil(event, func(a any) bool {
		return a != nil
	})
	if ret == nil {
		return nil
	}
	err, ok := ret.(error)
	if ok {
		return err
	} else {
		panic("unrecognized error happens in onAttach")
	}
}

// OnDetach is called when the node is detached from an engine
func (n *BaseNodeImpl) OnDetach() {
	n.OnDetachEvt.Dispatch(&Event{
		TargetNode: n.Node,
		Target:     nil,
	})
}

// (AI GENERATED DESCRIPTION): Attempts to cast the node to a `*BaseNodeImpl`; it returns the node itself if the target type is `*BaseNodeImpl`, otherwise it returns `nil`.
func (n *BaseNodeImpl) CastTo(ptr any) any {
	switch ptr.(type) {
	case (*BaseNodeImpl):
		return n
	default:
		return nil
	}
}

// (AI GENERATED DESCRIPTION): Returns the embedded Node instance associated with this BaseNodeImpl.
func (n *BaseNodeImpl) TreeNode() *Node {
	return n.Node
}

// (AI GENERATED DESCRIPTION): Creates a BaseNodeImpl that wraps the supplied Node and initializes its attach and detach event targets.
func CreateBaseNode(node *Node) NodeImpl {
	return &BaseNodeImpl{
		Node:        node,
		OnAttachEvt: &EventTarget{},
		OnDetachEvt: &EventTarget{},
	}
}

var BaseNodeDesc *NodeImplDesc

// (AI GENERATED DESCRIPTION): Initializes the base node implementation descriptor by assigning its class name, default attach/detach events, and creation function, then registers this descriptor with the system.
func initBaseNodeImplDesc() {
	BaseNodeDesc = &NodeImplDesc{
		ClassName:  "Base",
		Properties: map[PropKey]PropertyDesc{},
		Events: map[PropKey]EventGetter{
			PropOnAttach: DefaultEventTarget(PropOnAttach),
			PropOnDetach: DefaultEventTarget(PropOnDetach),
		},
		Functions: map[string]NodeFunc{},
		Create:    CreateBaseNode,
	}
	RegisterNodeImpl(BaseNodeDesc)
}
