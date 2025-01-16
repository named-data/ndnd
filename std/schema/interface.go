package schema

import (
	"fmt"
	"reflect"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

type PropertyDesc struct {
	Get func(owner any) any
	Set func(owner any, value any) error
}

type EventGetter func(owner any) *EventTarget

type NodeFunc func(mNode MatchedNode, args ...any) any

type NodeImplDesc struct {
	ClassName  string
	Properties map[PropKey]PropertyDesc
	Events     map[PropKey]EventGetter
	Create     func(*Node) NodeImpl
	Functions  map[string]NodeFunc
}

type PolicyImplDesc struct {
	ClassName  string
	Properties map[PropKey]PropertyDesc
	Events     map[PropKey]EventGetter
	Create     func() Policy
}

// NodeImpl represents the functional part of a node (subtree) of NTSchema.
// Besides functions listed here, NodeImpl also needs a creator that creates the Node.
type NodeImpl interface {
	// NodeImplTrait is the type trait of NTNode
	NodeImplTrait() NodeImpl

	// CastTo cast the current struct to a pointer which has the same type as ptr
	// Supposed to be used as:
	//
	//   leafNode.CastTo((*ExpressPoint)(nil))  // Get *ExpressPoint
	//
	// This is because `leafNode.(*ExpressPoint)` fails.
	CastTo(ptr any) any

	// OnInterest is the callback function when there is an incoming Interest.
	OnInterest(interest ndn.InterestHandlerArgs, matching enc.Matching)

	// OnAttach is called when the node is attached to an engine
	OnAttach() error

	// OnDetach is called when the node is detached from an engine
	OnDetach()

	// TreeNode returns the node container it is in.
	TreeNode() *Node
}

// NTPolicy represents a policy, which is a modifier that sets properties and registers events
// during the initialization of a schema tree.
// The execution order is: construct the tree -> apply policies & env setup -> attach to engine (see Tree)
// Though policies are also considered as static knowledge (at compile time),
// they may be configured differently on different nodes.
// For example, an storage may access different folders for different instances.
// TODO: Design for this configuration under different environments.
// For example, the path to a storage, the name of the self-key, etc are knowledge specific to one instance,
// and thus dynamically configured.
// Currently I don't have an idea on the best way to separate the "statically shared part" (NTTree and the nodes)
// and the "dynamically configure part". (#ENV)
type Policy interface {
	// PolicyTrait is the type trait of NTPolicy
	PolicyTrait() Policy

	// Apply the policy at a node (subtree). May modify the children of the given node.
	// The execution order is node.Init() -> policy.Apply() -> onAttach()
	// So the properties set here will overwrite Init()'s default values,
	// but be overwriten by onAttach().
	Apply(node *Node)
}

// PropKey is the type of properties of a node.
// A property of a node gives the default setting of some procedure as well as event callbacks.
// We design in this way to support DSL and WASM in future.
type PropKey string

// MatchedNode represents a node with a matching
type MatchedNode struct {
	Node     *Node
	Matching enc.Matching
	Name     enc.Name
}

// ValidRes is the result of data/interest signature validation, given by one validator.
// When there are multiple validators chained, a packet is valid when there is at least one VrPass and no VrFail.
type ValidRes = int

const (
	VrFail       ValidRes = -2 // An immediate failure. Abort the validation.
	VrTimeout    ValidRes = -1 // Timeout. Abort the validation.
	VrSilence    ValidRes = 0  // The current validator cannot give any result.
	VrPass       ValidRes = 1  // The current validator approves the packet.
	VrBypass     ValidRes = 2  // An immediate success. Bypasses the rest validators that are not executed yet.
	VrCachedData ValidRes = 3  // The data is obtained from a local cache, and the signature is checked before.
)

const (
	// The event called when the node is attached to an engine. [NodeOnAttachEvent]
	PropOnAttach PropKey = "OnAttachEvt"

	// The event called when the node is detached from an engine. [NodeOnDetachEvent]
	PropOnDetach PropKey = "OnDetachEvt"

	// The event called when an ExpressingPoint or LeafNode receives an Interest. [NodeOnIntEvent]
	PropOnInterest PropKey = "OnInt"

	// The event called when an ExpressingPoint or LeafNode verifies the signature of an Interest. [NodeValidateEvent]
	PropOnValidateInt PropKey = "OnValidateInt"

	// The event called when an ExpressingPoint or LeafNode verifies the signature of a Data. [NodeValidateEvent]
	PropOnValidateData PropKey = "OnValidateData"

	// The event called when an ExpressingPoint or LeafNode searches the storage on Need(). [NodeSearchStorageEvent]
	PropOnSearchStorage PropKey = "OnSearchStorage"

	// The event called to get a signer for an Interest
	PropOnGetIntSigner PropKey = "OnGetIntSigner"

	// The event called to get a signer for a Data
	PropOnGetDataSigner PropKey = "OnGetDataSigner"

	// The event called when an ExpressingPoint or LeafNode saves a packet into the storage.
	// The packet may be produced locally or fetched from the network.
	// TODO: Add a sign to distinguish them.
	// [NodeSaveStorageEvent]
	PropOnSaveStorage PropKey = "OnSaveStorage"

	// Default CanBePrefix for outgoing Interest. [bool]
	PropCanBePrefix PropKey = "CanBePrefix"
	// Default MustBeFresh for outgoing Interest. [bool]
	PropMustBeFresh PropKey = "MustBeFresh"
	// Default Lifetime for outgoing Interest. [time.Duration]
	PropLifetime PropKey = "Lifetime"
	// If true, only local storage is searched. No Interest will be expressed.
	// Note: may be overwritten by the Context.
	// [bool]
	PropSuppressInt PropKey = "SupressInt"

	// Default ContentType for produced Data. [ndn.ContentType]
	PropContentType PropKey = "ContentType"
	// Default FreshnessPeriod for produced Data. [time.Duration]
	PropFreshness PropKey = "Freshness"
	// How long the data is supposed to be stored in the storage. [time.Duration]
	// The validity period of a data in the storage produced by this node,
	// i.e. how long the local storage will serve it.
	// Should be larger than FreshnessPeriod. Not affected data fetched remotely.
	// This is only the rough way to express the life period of some temporary data.
	// For long durable data stored in databases, etc., the users should use the ways
	// specified by the storage developers to express the lifetime.
	PropValidDuration PropKey = "ValidDur"
)

// DefaultPropertyDesc returns the default property descriptor of given property name.
func DefaultPropertyDesc(prop PropKey) PropertyDesc {
	return PropertyDesc{
		Get: func(owner any) any {
			defer func() { recover() }() // Return nil for not existing field
			objval := reflect.ValueOf(owner)
			return objval.Elem().FieldByName(string(prop)).Interface()
		},
		Set: func(owner any, value any) (ret error) {
			ret = ndn.ErrInvalidValue{Item: string(prop), Value: value}
			defer func() { recover() }() // Return error
			objval := reflect.ValueOf(owner)
			// Need to handle a special case: if field is uint64, then it must accept float64 value
			field := objval.Elem().FieldByName(string(prop))
			if !field.CanSet() {
				ret = ndn.ErrNotSupported{Item: string(prop)}
			}
			if field.Kind() == reflect.Uint64 {
				switch v := value.(type) {
				case float64:
					field.SetUint(uint64(v))
				default:
					field.Set(reflect.ValueOf(value))
				}
			} else if field.Type() == reflect.TypeOf([]byte{}) {
				// Cast string to bytes
				switch v := value.(type) {
				case string:
					field.Set(reflect.ValueOf([]byte(v)))
				default:
					field.Set(reflect.ValueOf(value))
				}
			} else {
				field.Set(reflect.ValueOf(value))
			}
			ret = nil
			return
		},
	}
}

// DefaultEventTarget returns the default event target getter of given event name.
func DefaultEventTarget(event PropKey) EventGetter {
	return func(owner any) *EventTarget {
		val := reflect.ValueOf(owner).Elem()
		target := val.FieldByName(string(event)).Interface().(*EventTarget)
		return target
	}
}

// TimePropertyDesc returns the descriptor of a time property, which gives numbers&strings in milliseconds.
// Note: Get/Set functions are less used by the go program, as Go can access the field directly.
func TimePropertyDesc(prop PropKey) PropertyDesc {
	return PropertyDesc{
		Get: func(owner any) any {
			defer func() { recover() }() // Return nil for not existing field
			objval := reflect.ValueOf(owner)
			val := objval.Elem().FieldByName(string(prop)).Interface()
			return uint64(val.(time.Duration) / time.Millisecond)
		},
		Set: func(owner any, value any) (ret error) {
			ret = ndn.ErrInvalidValue{Item: string(prop), Value: value}
			defer func() { recover() }() // Return error
			objval := reflect.ValueOf(owner)
			field := objval.Elem().FieldByName(string(prop))
			switch v := value.(type) {
			case float32:
				field.Set(reflect.ValueOf(time.Duration(v * float32(time.Millisecond))))
				ret = nil
			case float64:
				field.Set(reflect.ValueOf(time.Duration(v * float64(time.Millisecond))))
				ret = nil
			case int64:
				field.Set(reflect.ValueOf(time.Duration(v) * time.Millisecond))
				ret = nil
			case uint64:
				field.Set(reflect.ValueOf(time.Duration(v) * time.Millisecond))
				ret = nil
			case int:
				field.Set(reflect.ValueOf(time.Duration(v) * time.Millisecond))
				ret = nil
			case uint:
				field.Set(reflect.ValueOf(time.Duration(v) * time.Millisecond))
				ret = nil
			}
			return
		},
	}
}

// MatchingPropertyDesc returns the descriptor of a `enc.Matching` property.
// It is of type `map[string]any` in JSON, where `any` is a string.
func MatchingPropertyDesc(prop PropKey) PropertyDesc {
	return PropertyDesc{
		Get: func(owner any) any {
			defer func() { recover() }() // Return nil for not existing field
			objval := reflect.ValueOf(owner)
			return objval.Elem().FieldByName(string(prop)).Interface().(enc.Matching)
		},
		Set: func(owner any, value any) (ret error) {
			ret = ndn.ErrInvalidValue{Item: string(prop), Value: value}
			defer func() { recover() }() // Return error
			objval := reflect.ValueOf(owner)
			field := objval.Elem().FieldByName(string(prop))
			input := value.(map[string]any)
			match := make(enc.Matching, len(input))
			// v could be []byte, uint64 or string
			for key, matchVal := range input {
				switch v := matchVal.(type) {
				case []byte:
					match[key] = v
				case uint64:
					match[key] = enc.Nat(v).Bytes()
				case string:
					comp, err := enc.ComponentFromStr(v)
					if err != nil {
						return
					}
					match[key] = comp.Val
				}
			}
			field.Set(reflect.ValueOf(match))
			ret = nil
			return
		},
	}
}

// SubNodePropertyDesc inherites a subnode's property as a property of the subtree's root.
func SubNodePropertyDesc(pathStr string, prop PropKey) PropertyDesc {
	path, err := enc.NamePatternFromStr(pathStr)
	if err != nil {
		panic(fmt.Errorf("invalid pattern string %s: %v", pathStr, err))
	}
	return PropertyDesc{
		Get: func(owner any) any {
			defer func() { recover() }() // Return nil for not existing path
			subNode := owner.(NodeImpl).TreeNode().At(path)
			return subNode.Get(prop)
		},
		Set: func(owner any, value any) (ret error) {
			ret = ndn.ErrInvalidValue{Item: string(prop), Value: value}
			defer func() { recover() }() // Return error
			subNode := owner.(NodeImpl).TreeNode().At(path)
			return subNode.Set(prop, value)
		},
	}
}

// NamePropertyDesc returns the descriptor of a enc.Name property, which gives an NDN Name in string.
// Note: Get/Set functions are less used by the go program, as Go can access the field directly.
func NamePropertyDesc(prop PropKey) PropertyDesc {
	return PropertyDesc{
		Get: func(owner any) any {
			defer func() { recover() }() // Return nil for not existing field
			objval := reflect.ValueOf(owner)
			val := objval.Elem().FieldByName(string(prop)).Interface()
			return val.(enc.Name).String()
		},
		Set: func(owner any, value any) (ret error) {
			ret = ndn.ErrInvalidValue{Item: string(prop), Value: value}
			defer func() { recover() }() // Return error
			objval := reflect.ValueOf(owner)
			field := objval.Elem().FieldByName(string(prop))
			switch v := value.(type) {
			case enc.Name:
				field.Set(reflect.ValueOf(v))
				ret = nil
			case string:
				name, err := enc.NameFromStr(v)
				if err != nil {
					field.Set(reflect.ValueOf(name))
					ret = nil
				}
			}
			return
		},
	}
}

// Call calls the specified function provided by the node with given arguments.
func (mNode MatchedNode) Call(funcName string, args ...any) any {
	f, ok := mNode.Node.desc.Functions[funcName]
	if !ok {
		return fmt.Errorf("not existing function %s", funcName)
	}
	return f(mNode, args...)
}

// QueryInterface casts a node to a specific NodeImpl type
func QueryInterface[T NodeImpl](node *Node) T {
	defer func() { recover() }()
	var zero T // Should be nil
	ret := node.impl.CastTo(zero)
	return ret.(T) // Will panic if it is nil, and then recover to nil
}

// Refine a matching with a longer name. `name` must include current name as a prefix.
func (mNode MatchedNode) Refine(name enc.Name) *MatchedNode {
	if !mNode.Name.IsPrefix(name) {
		if mNode.Name[len(mNode.Name)-1].Typ != enc.TypeImplicitSha256DigestComponent ||
			!mNode.Name[:len(mNode.Name)-1].Equal(name) {
			return nil
		} else {
			mNode.Name = name
			return &mNode
		}
	}
	match := make(enc.Matching, len(mNode.Matching))
	for k, v := range mNode.Matching {
		match[k] = v
	}
	node := mNode.Node.ContinueMatch(name[len(mNode.Name):], match)
	if node != nil {
		return &MatchedNode{
			Node:     node,
			Name:     name,
			Matching: match,
		}
	} else {
		return nil
	}
}
