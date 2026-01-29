package trust_schema

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
)

const LVS_VERSION uint64 = 0x00011000

type LvsSchema struct {
	m *LvsModel
}

type LvsCtx = map[uint64]enc.Component

// (AI GENERATED DESCRIPTION): Creates an LvsSchema from raw bytes by parsing the LVSC model and verifying that its version, node IDs, edges, sign‑constraint references, and constraint options are all valid before returning the schema or an error.
func NewLvsSchema(buf []byte) (*LvsSchema, error) {
	model, err := ParseLvsModel(enc.NewBufferView(buf), false)
	if err != nil {
		return nil, err
	}

	// https://python-ndn.readthedocs.io/en/latest/src/lvs/binary-format.html

	// Sanity: Version is supported.
	if model.Version != LVS_VERSION {
		return nil, fmt.Errorf("invalid light versec schema version")
	}

	for i, node := range model.Nodes {
		// Sanity: Every node’s NodeId equals to its index in the array.
		if node.Id != uint64(i) {
			return nil, fmt.Errorf("invalid node id")
		}

		// Sanity: All edges refer to existing destination node ID.
		for _, edge := range node.Edges {
			if edge.Dest >= uint64(len(model.Nodes)) {
				return nil, fmt.Errorf("invalid edge destination")
			}

			// Sanity: Every edge's destination sets parent to the source of the edge.
			// This guarantees all nodes reachable from the root is a tree.
			parent := model.Nodes[edge.Dest].Parent
			if pval, ok := parent.Get(); !ok || pval != node.Id {
				return nil, errors.New("invalid edge parent")
			}
		}

		// Sanity: Every SignConstraint refers to an existing destination node ID
		for _, sc := range node.SignCons {
			if sc >= uint64(len(model.Nodes)) {
				return nil, fmt.Errorf("invalid sign constraint destination")
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
					if opt.Tag.IsSet() {
						count++
					}
					if opt.Fn != nil {
						count++
					}
					if count != 1 {
						return nil, fmt.Errorf("invalid constraint option")
					}
				}
			}
		}
	}

	return &LvsSchema{m: model}, nil
}

// (AI GENERATED DESCRIPTION): Collects all `LvsNode` objects that match the given name in the `LvsSchema` and returns them as a slice.
func (s *LvsSchema) MatchCollect(name enc.Name) []*LvsNode {
	nodes := make([]*LvsNode, 0)
	for node := range s.Match(name, nil) {
		nodes = append(nodes, node)
	}
	return nodes
}

// (AI GENERATED DESCRIPTION): Yields every pair of LvsNode and its variable‑binding context that matches the supplied name against the schema, performing a depth‑first traversal of value and pattern edges with backtracking to enumerate all successful matches.
func (s *LvsSchema) Match(name enc.Name, startCtx LvsCtx) iter.Seq2[*LvsNode, LvsCtx] {
	return func(yield func(*LvsNode, LvsCtx) bool) {
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
		context := make(LvsCtx, len(name))
		maps.Copy(context, startCtx)

		// Depth-first search
		for cur != nil {
			depth := len(edge_indices)
			backtrack := false

			// If match succeeds
			if depth == len(name) {
				if !yield(cur, context) {
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

				if pval, ok := cur.Parent.Get(); ok {
					cur = s.m.Nodes[pval]
				} else {
					cur = nil
				}
			}
		}
	}
}

// (AI GENERATED DESCRIPTION): Verifies that the specified key name is authorized to sign the given packet name under the current Lvs schema.
func (s *LvsSchema) Check(pkt enc.Name, key enc.Name) bool {
	for pktNode, pktCtx := range s.Match(pkt, nil) {
		for keyNode := range s.Match(key, pktCtx) {
			if s.checkSigner(pktNode, keyNode) {
				return true
			}
		}
	}
	return false
}

// (AI GENERATED DESCRIPTION): Suggest selects a signer from a keychain whose certificate matches the packet name under the current LvsSchema and returns a ContextSigner that will sign the packet with that key, or nil if no suitable signer is found.
func (s *LvsSchema) Suggest(pkt enc.Name, keychain ndn.KeyChain) ndn.Signer {
	// O(n^7) ... but n is small
	for pktNode, pktCtx := range s.Match(pkt, nil) {
		for _, id := range keychain.Identities() {
			for _, key := range id.Keys() {
				for _, cert := range key.UniqueCerts() {
					for keyNode := range s.Match(cert, pktCtx) {
						if !s.checkSigner(pktNode, keyNode) {
							continue
						}

						// Load the real cert
						wire, err := keychain.Store().Get(cert.Prefix(-1), true)
						if err != nil || wire == nil {
							continue
						}

						certData, _, err := spec.Spec{}.ReadData(enc.NewWireView(enc.Wire{wire}))
						if err != nil {
							continue
						}

						_, notAfter := certData.Signature().Validity()
						if val, ok := notAfter.Get(); ok && val.After(time.Now()) {
							return sig.WithKeyLocator(key.Signer(), cert[:len(cert)-1]) // remove version
						}
					}
				}
			}
		}
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Checks whether a name component satisfies all given pattern constraints by matching it against literal values or context tags, returning true only if every constraint is met.
func (s *LvsSchema) checkCons(
	value enc.Component,
	context LvsCtx,
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
			} else if tag, ok := op.Tag.Get(); ok {
				if value.Equal(context[tag]) {
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

// (AI GENERATED DESCRIPTION): Checks whether a packet node is signed by a given key node by verifying that the key node’s ID appears in the packet’s SignCons list.
func (s *LvsSchema) checkSigner(pktNode *LvsNode, keyNode *LvsNode) bool {
	return slices.Contains(pktNode.SignCons, keyNode.Id)
}
