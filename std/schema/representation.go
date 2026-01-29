package schema

import (
	"encoding/json"
	"fmt"

	enc "github.com/named-data/ndnd/std/encoding"
)

type SchemaDesc struct {
	Nodes    map[string]NodeDesc `json:"nodes"`
	Policies []PolicyDesc        `json:"policies"`
}

type ListenerList []string

type NodeDesc struct {
	Type   string                  `json:"type"`
	Attrs  map[string]any          `json:"attrs,omitempty"`
	Events map[string]ListenerList `json:"events,omitempty"`
}

type PolicyDesc struct {
	Type   string                  `json:"type"`
	Path   string                  `json:"path"`
	Attrs  map[string]any          `json:"attrs,omitempty"`
	Events map[string]ListenerList `json:"events,omitempty"`
}

var NodeRegister map[string]*NodeImplDesc
var PolicyRegister map[string]*PolicyImplDesc

// (AI GENERATED DESCRIPTION): Registers a Node implementation descriptor by its class name, adding it to the global registry and panicking if the name is already registered.
func RegisterNodeImpl(desc *NodeImplDesc) {
	name := desc.ClassName
	if _, ok := NodeRegister[name]; ok {
		panic(fmt.Sprintf("NodeImpl class %s has already been registered", name))
	}
	NodeRegister[name] = desc
}

// (AI GENERATED DESCRIPTION): Registers a policy implementation descriptor, panicking if the class name has already been registered.
func RegisterPolicyImpl(desc *PolicyImplDesc) {
	name := desc.ClassName
	if _, ok := PolicyRegister[name]; ok {
		panic(fmt.Sprintf("Policy class %s has already been registered", name))
	}
	PolicyRegister[name] = desc
}

// (AI GENERATED DESCRIPTION): Instantiates event callbacks by resolving each listener name in the event map against the provided environment, producing a map of event keys to slices of Callback functions and panicking if any name is missing.
func instantiateEvents(events map[string]ListenerList, env map[string]any) map[string][]Callback {
	ret := make(map[string][]Callback, len(events))
	for k, lst := range events {
		ret[k] = make([]Callback, len(lst))
		for i, name := range lst {
			if cb, ok := env[name].(Callback); ok {
				ret[k][i] = cb
			} else {
				panic(fmt.Errorf("missing callback event %s in the environment", name))
			}
		}
	}
	return ret
}

// (AI GENERATED DESCRIPTION): Recursively replaces any string beginning with `$` in the attributes map with the corresponding value from the provided environment map, panicking if a referenced attribute is missing.
func instantiateAttrs(attrs map[string]any, env map[string]any) map[string]any {
	var handleList func([]any) []any
	var handleMap func(map[string]any) map[string]any
	handleVal := func(val any) any {
		switch v := val.(type) {
		case string:
			if len(v) == 0 || v[0] != '$' {
				return v
			}
			if attr, ok := env[v]; ok {
				return attr
			} else {
				panic(fmt.Errorf("missing attributes %s in the environment", v))
			}
			// Recursive if ret is a list or another map
		case map[string]any:
			return handleMap(v)
		case []any:
			return handleList(v)
		default:
			return v
		}
	}
	handleMap = func(mp map[string]any) map[string]any {
		ret := make(map[string]any, len(mp))
		for k, val := range mp {
			ret[k] = handleVal(val)
		}
		return ret
	}
	handleList = func(lst []any) []any {
		ret := make([]any, len(lst))
		for i, val := range lst {
			ret[i] = handleVal(val)
		}
		return ret
	}

	return handleMap(attrs)
}

// (AI GENERATED DESCRIPTION): Instantiates a schema tree by creating nodes and policies defined in the SchemaDesc, applying attributes and events resolved against the supplied environment map, and returns the fully constructed Tree.
func (sd *SchemaDesc) Instantiate(environment map[string]any) *Tree {
	// Events must be Callbacks
	// Attrs has nested maps that needs to be handled
	tree := &Tree{}
	// Handle nodes
	for pathStr, node := range sd.Nodes {
		path, err := enc.NamePatternFromStr(pathStr)
		if err != nil {
			panic(fmt.Errorf("unable to instantiate schema tree: invalid path '%s': %v", pathStr, err))
		}
		// Create nodes
		nodeDesc, ok := NodeRegister[node.Type]
		if !ok {
			panic(fmt.Errorf("unable to instantiate schema tree: invalid node type '%s'", node.Type))
		}
		impl := tree.PutNode(path, nodeDesc).Impl()
		// Set attributes
		attrs := instantiateAttrs(node.Attrs, environment)
		for k, v := range attrs {
			// If there is a #, then it's for sub child
			err := nodeDesc.Properties[PropKey(k)].Set(impl, v)
			if err != nil {
				panic(fmt.Errorf("unable to instantiate schema tree: invalid attribute '%s'=%v: %v", k, v, err))
			}
		}
		// Set events
		events := instantiateEvents(node.Events, environment)
		for k, lst := range events {
			evtTgt := nodeDesc.Events[PropKey(k)](impl)
			for _, cb := range lst {
				v := cb // Capture the value
				evtTgt.Add(&v)
			}
		}
	}
	// Handle policies
	for _, policy := range sd.Policies {
		pathStr := policy.Path
		path, err := enc.NamePatternFromStr(pathStr)
		if err != nil {
			panic(fmt.Errorf("unable to instantiate schema tree: invalid path '%s': %v", pathStr, err))
		}
		node := tree.At(path)
		if node == nil {
			panic(fmt.Errorf("unable to instantiate schema tree: not existing path '%s' to attach policy", pathStr))
		}
		// Create policies
		policyDesc, ok := PolicyRegister[policy.Type]
		if !ok {
			panic(fmt.Errorf("unable to instantiate schema tree: invalid policy type '%s'", policy.Type))
		}
		inst := policyDesc.Create()
		// Set attributes
		attrs := instantiateAttrs(policy.Attrs, environment)
		for k, v := range attrs {
			err := policyDesc.Properties[PropKey(k)].Set(inst, v)
			if err != nil {
				panic(fmt.Errorf("unable to instantiate schema tree: invalid attribute '%s'=%v: %v", k, v, err))
			}
		}
		// Set events
		events := instantiateEvents(policy.Events, environment)
		for k, lst := range events {
			evtTgt := policyDesc.Events[PropKey(k)](inst)
			for _, cb := range lst {
				v := cb // Capture the value
				evtTgt.Add(&v)
			}
		}
		// Apply policy
		inst.Apply(node)
	}
	return tree
}

// CreateFromJson creates a schema tree from json description and a given environment
func CreateFromJson(text string, environment map[string]any) *Tree {
	schemaDesc := &SchemaDesc{}
	err := json.Unmarshal([]byte(text), schemaDesc)
	if err != nil {
		panic("unable to parse json")
	}
	return schemaDesc.Instantiate(environment)
}
