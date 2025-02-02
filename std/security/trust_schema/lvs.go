package trust_schema

import (
	"bytes"
	"errors"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	sig "github.com/named-data/ndnd/std/security/signer"
)

const LVS_VERSION uint64 = 0x00011000

type LvsSchema struct {
	m *LvsModel
}

func NewLvsSchema(buf []byte) (*LvsSchema, error) {
	model, err := ParseLvsModel(enc.NewFastBufReader(buf), false)
	if err != nil {
		return nil, err
	}

	// https://python-ndn.readthedocs.io/en/latest/src/lvs/binary-format.html

	// Sanity: Version is supported.
	if model.Version != LVS_VERSION {
		return nil, errors.New("invalid light versec schema version")
	}

	for i, node := range model.Nodes {
		// Sanity: Every node’s NodeId equals to its index in the array.
		if node.Id != uint64(i) {
			return nil, errors.New("invalid node id")
		}

		// Sanity: All edges refer to existing destination node ID.
		for _, edge := range node.Edges {
			if edge.Dest >= uint64(len(model.Nodes)) {
				return nil, errors.New("invalid edge destination")
			}

			// Sanity: Every edge's destination sets parent to the source of the edge.
			// This guarantees all nodes reachable from the root is a tree.
			parent := model.Nodes[edge.Dest].Parent
			if parent == nil || *parent != node.Id {
				return nil, errors.New("invalid edge parent")
			}
		}

		// Sanity: Every SignConstraint refers to an existing destination node ID
		for _, sc := range node.SignCons {
			if sc >= uint64(len(model.Nodes)) {
				return nil, errors.New("invalid sign constraint destination")
			}
		}

		// Sanity: For each ConstraintOption, exactly one of Value, Tag and UserFn is set.
		for _, pe := range node.PatternEdges {
			for _, co := range pe.ConsSets {
				for _, opt := range co.ConsOptions {
					count := 0
					if opt.Value != nil {
						count++
					}
					if opt.Tag != nil {
						count++
					}
					if opt.Fn != nil {
						count++
					}
					if count != 1 {
						return nil, errors.New("invalid constraint option")
					}
				}
			}
		}
	}

	return &LvsSchema{m: model}, nil
}

func (s *LvsSchema) Match(name enc.Name) []*LvsNode {
	nodes := make([]*LvsNode, 0)
	s.match_(name, nil, func(node *LvsNode, ctx map[uint64]enc.Component) bool {
		nodes = append(nodes, node)
		return true
	})
	return nodes
}

func (s *LvsSchema) match_(
	name enc.Name, startCtx map[uint64]enc.Component,
	callback func(node *LvsNode, ctx map[uint64]enc.Component) bool,
) {
	// Empty name never matches
	if len(name) == 0 {
		return
	}

	// Remove the implicit SHA-256 digest component
	if name.At(-1).Typ == enc.TypeImplicitSha256DigestComponent {
		name = name.Prefix(-1)
	}

	// Current node in the depth-first search
	cur := s.m.Nodes[s.m.StartId]

	// Edge index being checked in this cycle
	//  -1 = check value nodes
	//  0 <= x < len(cur.PatternEdges) = check pattern nodes
	//  len(cur.PatternEdges) = backtrack
	edge_index := -1

	// Edge stack for backtracking
	edge_indices := make([]int, 0, len(name))

	// Matched tags for backtracking
	matches := make([]int, 0, len(name))

	// Tag -> name component mapping
	context := make(map[uint64]enc.Component, len(name))
	for k, v := range startCtx {
		context[k] = v
	}

	// Depth-first search
	for cur != nil {
		depth := len(edge_indices)
		backtrack := false

		// If match succeeds
		if depth == len(name) {
			if !callback(cur, context) {
				return
			}
			backtrack = true
		} else {
			// Make movements
			if edge_index < 0 {
				// Value edge: since it matches at most once, ignore edge_index
				edge_index = 0
				for _, ve := range cur.Edges {
					if bytes.Equal(name[depth].Bytes(), ve.Value) { // TODO: optimize
						edge_indices = append(edge_indices, 0)
						matches = append(matches, -1)
						cur = s.m.Nodes[ve.Dest]
						edge_index = -1
						break
					}
				}
			} else if edge_index < len(cur.PatternEdges) {
				// Pattern edge: check condition and make a move
				pe := cur.PatternEdges[edge_index]
				edge_index++

				if _, ok := context[pe.Tag]; ok {
					if !name[depth].Equal(context[pe.Tag]) {
						continue
					}
					matches = append(matches, -1)
				} else {
					if !s.checkCons(name[depth], context, pe.ConsSets) {
						continue
					}
					if pe.Tag <= s.m.NamedPatternCnt {
						context[pe.Tag] = name[depth]
						matches = append(matches, int(pe.Tag))
					} else {
						matches = append(matches, -1)
					}
				}

				edge_indices = append(edge_indices, edge_index)
				cur = s.m.Nodes[pe.Dest]
				edge_index = -1
			} else {
				backtrack = true
			}
		}

		if backtrack {
			if len(edge_indices) > 0 {
				edge_index = edge_indices[len(edge_indices)-1]
				edge_indices = edge_indices[:len(edge_indices)-1]
			}

			if len(matches) > 0 {
				last_tag := matches[len(matches)-1]
				matches = matches[:len(matches)-1]
				if last_tag >= 0 {
					delete(context, uint64(last_tag))
				}
			}

			if cur.Parent != nil {
				cur = s.m.Nodes[*cur.Parent]
			} else {
				cur = nil
			}
		}
	}
}

func (s *LvsSchema) Check(pkt enc.Name, key enc.Name) bool {
	matched := false
	s.match_(pkt, nil, func(pktNode *LvsNode, pktCtx map[uint64]enc.Component) bool {
		s.match_(key, pktCtx, func(keyNode *LvsNode, _ map[uint64]enc.Component) bool {
			if s.checkSigner(pktNode, keyNode) {
				matched = true
			}
			return !matched
		})
		return !matched
	})
	return matched
}

func (s *LvsSchema) Suggest(pkt enc.Name, keychain ndn.KeyChain) ndn.Signer {
	var signer ndn.Signer = nil

	// O(n^7) ... but n is small
	s.match_(pkt, nil, func(pktNode *LvsNode, pktCtx map[uint64]enc.Component) bool {
		for _, id := range keychain.Identities() {
			for _, key := range id.Keys() {
				for _, cert := range key.UniqueCerts() {
					s.match_(cert, pktCtx, func(keyNode *LvsNode, _ map[uint64]enc.Component) bool {
						if s.checkSigner(pktNode, keyNode) {
							signer = &sig.ContextSigner{
								Signer:         key.Signer(),
								KeyLocatorName: cert[:len(cert)-1], // remove version
							}
						}

						return signer == nil
					})
				}
			}
		}

		return signer == nil
	})

	return signer
}

func (s *LvsSchema) checkCons(
	value enc.Component,
	context map[uint64]enc.Component,
	consSet []*LvsPatternConstraint,
) bool {
	for _, cons := range consSet {
		satisfied := false
		for _, op := range cons.ConsOptions {
			if op.Value != nil {
				if bytes.Equal(value.Bytes(), op.Value) {
					satisfied = true
					break
				}
			} else if op.Tag != nil {
				if value.Equal(context[*op.Tag]) {
					satisfied = true
					break
				}
			} else if op.Fn != nil {
				// user functions are not supported
				panic("LVS user functions are not supported")
			} else {
				panic("invalid constraint option")
			}
		}
		if !satisfied {
			return false
		}
	}
	return true
}

func (s *LvsSchema) checkSigner(pktNode *LvsNode, keyNode *LvsNode) bool {
	for _, sc := range pktNode.SignCons {
		if keyNode.Id == sc {
			return true
		}
	}
	return false
}
