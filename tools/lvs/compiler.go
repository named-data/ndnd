package lvs

import (
	"cmp"
	"encoding/hex"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"

	trust "github.com/named-data/ndnd/std/security/trust_schema"
	"github.com/named-data/ndnd/std/types/optional"
)

type Compiler struct {
	lvsFile      LvsFile
	ruleIds      []string
	ruleRefs     map[string][]string
	namedPats    map[string]string
	repRules     map[string][]RuleChain
	nodePool     []*trust.LvsNode
	tempTagIndex int
	ruleNodeIds  map[string][]uint64
	signConStrs  map[uint64][]string
}

type RuleChain struct {
	id       string
	name     []NameComp
	consSet  []TagConstraint
	signCons []string
}

type PMove struct {
	tag        int
	consSet    []*trust.LvsPatternConstraint
	consSetStr string
	rc         RuleChain
}

func (rc *RuleChain) patternMovement(depth int, prevTags map[int]struct{}) PMove {
	if rc.name[depth].pat.id == "" {
		return PMove{0, nil, "", *rc}
	}

	tag, _ := strconv.Atoi(rc.name[depth].pat.id)

	if _, prev := prevTags[tag]; prev {
		return PMove{tag, nil, strconv.Itoa(tag) + ":", *rc}
	}

	var consSet []*trust.LvsPatternConstraint

	consSetStr := strconv.Itoa(tag) + ":"

	for _, cons := range rc.consSet {
		tagStrs := strings.Split(cons.pat.id, " ")
		tags := make([]int, len(tagStrs))
		for i, tag := range tagStrs {
			tagString, _ := strconv.Atoi(tag)
			tags[i] = tagString
		}

		if !slices.Contains(tags, tag) {
			continue
		}

		var encodedCons trust.LvsPatternConstraint
		consSetStr += "{"

		for _, opt := range cons.options {
			var encodedOpt trust.LvsConstraintOption

			if opt.compVal.c != nil {
				encodedOpt.Value = opt.compVal.c
				consSetStr += "v=" + hex.EncodeToString(opt.compVal.c)
			} else if opt.pat.id != "" {
				p, _ := strconv.Atoi(opt.pat.id)
				encodedOpt.Tag = optional.Some(uint64(p))
				consSetStr += "t=" + opt.pat.id
			} else if opt.fnCall.name != "" {
				// TODO: implement fncall
			}

			encodedCons.ConsOptions = append(encodedCons.ConsOptions, &encodedOpt)
			consSetStr += ","
		}
		consSetStr += "}"
		consSet = append(consSet, &encodedCons)
	}

	return PMove{tag, consSet, consSetStr, *rc}
}

func (c *Compiler) fixSigningReferences() {
	for i := range c.nodePool {
		var signCons []uint64
		for _, rid := range c.signConStrs[c.nodePool[i].Id] {
			// TODO: add non-existing key signature check
			signCons = append(signCons, c.ruleNodeIds[rid]...)
		}
		slices.Sort(signCons)
		c.nodePool[i].SignCons = signCons
	}
}

func NewCompiler(lvsFile LvsFile) *Compiler {
	return &Compiler{lvsFile: lvsFile}
}

func (c *Compiler) compile() trust.LvsModel {
	c.sortRuleReferences()
	c.genPatternNumbers()
	c.replicateRules()

	var sortedRepRules [][]RuleChain

	for _, rc := range c.repRules {
		sortedRepRules = append(sortedRepRules, rc)
	}

	slices.SortFunc(sortedRepRules, func(a, b []RuleChain) int {
		return cmp.Compare(a[0].id, b[0].id)
	})

	var ruleChains []RuleChain

	for _, rc := range sortedRepRules {
		ruleChains = append(ruleChains, rc...)
	}

	c.tempTagIndex = len(c.namedPats)

	c.ruleNodeIds = make(map[string][]uint64)
	c.signConStrs = make(map[uint64][]string)

	startNode := c.generateNode(0, ruleChains, optional.None[uint64](), make(map[int]struct{}))

	c.fixSigningReferences()

	var symbols []*trust.LvsTagSymbol

	for pName, tag := range c.namedPats {
		tagInt, _ := strconv.Atoi(tag)
		symbols = append(symbols, &trust.LvsTagSymbol{
			Ident: []byte(pName),
			Tag:   optional.Some(uint64(tagInt)),
		})
	}

	slices.SortFunc(symbols, func(a, b *trust.LvsTagSymbol) int {
		ca, _ := a.Tag.Get()
		cb, _ := b.Tag.Get()
		return cmp.Compare(ca, cb)
	})

	return trust.LvsModel{
		Version:         trust.LVS_VERSION,
		StartId:         startNode,
		NamedPatternCnt: uint64(len(c.namedPats)),
		Nodes:           c.nodePool,
		Symbols:         symbols,
	}
}

func (c *Compiler) sortRuleReferences() {
	ruleIdSet := make(map[string]struct{})
	tempRuleNumber := 1

	for _, rule := range c.lvsFile.rules {
		if rule.id.id[1] == '_' {
			rule.id.id += "#" + strconv.Itoa(tempRuleNumber)
			tempRuleNumber++
		}

		ruleIdSet[rule.id.id] = struct{}{}
	}

	adjList := make(map[string][]string)

	for _, rule := range c.lvsFile.rules {
		for _, comp := range rule.name.p {
			if comp.ruleId.id != "" {
				// if _, ok := ruleIdSet[comp]; !ok { // nonexisting
				// if comp.ruleId.id[1] == "_" { // temporary reference
				adjList[rule.id.id] = append(adjList[rule.id.id], comp.ruleId.id)
			}
		}
	}

	c.ruleIds = topOrder(ruleIdSet, adjList)
	c.ruleRefs = adjList

	idxLookup := make(map[string]int)
	for i, ruleId := range c.ruleIds {
		idxLookup[ruleId] = i
	}

	slices.SortStableFunc(c.lvsFile.rules, func(a, b Rule) int {
		return cmp.Compare(idxLookup[a.id.id], idxLookup[b.id.id])
	})
}

func topOrder[T cmp.Ordered](nodes map[T]struct{}, graph map[T][]T) []T {
	inDegrees := make(map[T]int)

	for node := range nodes {
		inDegrees[node] = 0
	}

	for _, edges := range graph {
		for _, dst := range edges {
			// TODO: check if src and dst in nodes
			inDegrees[dst]++
		}
	}

	var sorted []T

	for len(sorted) < len(nodes) {
		var currentRound []T

		for node, inDegree := range inDegrees {
			if inDegree == 0 {
				currentRound = append(currentRound, node)
			}
		}

		if len(currentRound) == 0 {
			panic("can")
		}

		// TODO: check if current round is empty, if so, it's loop
		slices.Sort(currentRound)

		for _, src := range currentRound {
			for _, dst := range graph[src] {
				inDegrees[dst]--
			}
			inDegrees[src] = -1
			sorted = append(sorted, src)
		}
	}

	slices.Reverse(sorted)
	return sorted
}

func (c *Compiler) genPatternNumbers() {
	c.namedPats = make(map[string]string)
	nextNamed := 1
	nextTemp := -1

	for rInd := range c.lvsFile.rules {
		rule := &c.lvsFile.rules[rInd]

		tempPats := make(map[string][]string)
		for pInd := range rule.name.p {
			comp := &rule.name.p[pInd]
			if comp.pat.id == "" {
				continue
			}

			patId := comp.pat.id

			if patId[0] == '_' {
				comp.pat.id = strconv.Itoa(nextTemp)
				nextTemp--

				tempPats[patId] = append(tempPats[patId], comp.pat.id)
			} else {
				if _, ok := c.namedPats[patId]; ok {
					comp.pat.id = c.namedPats[patId]
				} else {
					comp.pat.id = strconv.Itoa(nextNamed)
					nextNamed++
					c.namedPats[patId] = comp.pat.id
				}
			}
		}

		for conInd := range rule.compCons {
			conSet := &rule.compCons[conInd]
			for k := range *conSet {
				con := &(*conSet)[k]
				if con.pat.id[0] == '_' {
					var sb strings.Builder

					for _, pat := range tempPats[con.pat.id] {
						sb.WriteString(" " + pat)
					}

					con.pat.id = sb.String()
				} else {
					con.pat.id = c.namedPats[con.pat.id]
				}

				for opInd := range con.options {
					op := &(con.options)[opInd]
					if op.pat.id != "" {
						// if op.pat.id[0] == '_' {
						op.pat.id = c.namedPats[op.pat.id]
						// TODO: add else for if it is temporary, which should not be used in pattern constraint
					} else if op.fnCall.name != "" {
						for _, arg := range op.fnCall.args {
							if arg.pat.id == "" {
								continue
							}

							// if arg.pat.id[0] == '_' {
							arg.pat.id = c.namedPats[arg.pat.id]
							// TODO: add else for if temporary
						}
					}
				}
			}
		}
	}
}

func (c *Compiler) replicateRules() {
	c.repRules = make(map[string][]RuleChain)
	for _, rule := range c.lvsFile.rules {
		var curChains []RuleChain
		var signCons []string
		for _, signCon := range rule.signCons {
			signCons = append(signCons, signCon.id)
		}
		slices.Sort(signCons)

		if len(rule.compCons) == 0 {
			curChains = []RuleChain{{id: rule.id.id,
				name:     []NameComp{},
				consSet:  []TagConstraint{},
				signCons: signCons}}
		} else {
			for _, consSet := range rule.compCons {
				curChains = append(curChains, RuleChain{id: rule.id.id,
					name:     []NameComp{},
					consSet:  consSet,
					signCons: signCons})
			}
		}

		for _, comp := range rule.name.p {
			if comp.compVal.c != nil || comp.pat.id != "" {
				for i := range curChains {
					curChains[i].name = append(curChains[i].name, comp)
				}
			} else {
				var newChains []RuleChain
				for _, refChain := range c.repRules[comp.ruleId.id] {
					for _, chain := range curChains {
						newChains = append(newChains, RuleChain{id: rule.id.id,
							name:     append(slices.Clone(chain.name), refChain.name...),
							consSet:  append(slices.Clone(chain.consSet), refChain.consSet...),
							signCons: chain.signCons})
					}
				}

				// TODO: check newChains is not empty
				curChains = newChains
			}
		}

		if _, ok := c.repRules[rule.id.id]; !ok {
			c.repRules[rule.id.id] = curChains
		} else {
			c.repRules[rule.id.id] = append(c.repRules[rule.id.id], curChains...)
		}

	}
}

func (c *Compiler) generateNode(depth int, context []RuleChain, parent optional.Optional[uint64], prevTags map[int]struct{}) uint64 {
	var node trust.LvsNode
	node.Id = uint64(len(c.nodePool))

	c.nodePool = append(c.nodePool, &node)
	node.Parent = parent
	var newContext []RuleChain

	for _, rc := range context {
		if depth == len(rc.name) {
			node.RuleName = append(node.RuleName, []byte(rc.id))
			c.ruleNodeIds[rc.id] = append(c.ruleNodeIds[rc.id], node.Id)
			c.signConStrs[node.Id] = append(c.signConStrs[node.Id], rc.signCons...)
		} else {
			newContext = append(newContext, rc)
		}
	}

	context = newContext

	vMove := make(map[string]struct{})

	for _, rc := range context {
		if rc.name[depth].compVal.c != nil {
			vMove[string(rc.name[depth].compVal.c)] = struct{}{}
		}
	}

	vMoveList := make([]string, 0, len(vMove))
	for v := range vMove {
		vMoveList = append(vMoveList, v)
	}
	slices.Sort(vMoveList)

	for _, v := range vMoveList {
		newContext = make([]RuleChain, 0)
		for _, rc := range context {
			if string(rc.name[depth].compVal.c) == v {
				newContext = append(newContext, rc)
			}
		}

		var edge trust.LvsValueEdge
		edge.Value = []byte(v)
		edge.Dest = c.generateNode(depth+1, newContext, optional.Some(node.Id), prevTags)
		node.Edges = append(node.Edges, &edge)
	}

	var pMoves []PMove
	var pMoveStrs []string
	pMoveStrSet := make(map[string]struct{})

	for _, rc := range context {
		if rc.name[depth].pat.id == "" {
			continue
		}

		pMoves = append(pMoves, rc.patternMovement(depth, prevTags))
	}
	for _, pm := range pMoves {
		pMoveStrSet[pm.consSetStr] = struct{}{}
	}
	for pms := range pMoveStrSet {
		pMoveStrs = append(pMoveStrs, pms)
	}

	slices.Sort(pMoveStrs)

	for _, pmStr := range pMoveStrs {
		newContext = make([]RuleChain, 0)

		tag := math.MaxInt // TODO: make this cleaner
		var consSets []*trust.LvsPatternConstraint
		for _, pm := range pMoves {
			if pm.consSetStr == pmStr {
				newContext = append(newContext, pm.rc)
				if tag == math.MaxInt {
					tag = pm.tag
					consSets = pm.consSet
				}
			}
		}

		// TODO: check if newContext is empty here

		var edge trust.LvsPatternEdge
		if tag >= 0 {
			edge.Tag = uint64(tag)
		} else {
			c.tempTagIndex += 1
			edge.Tag = uint64(c.tempTagIndex)
		}
		edge.ConsSets = consSets
		newPrevTags := maps.Clone(prevTags)
		newPrevTags[tag] = struct{}{}
		edge.Dest = c.generateNode(depth+1, newContext, optional.Some(node.Id), newPrevTags)
		node.PatternEdges = append(node.PatternEdges, &edge)
	}
	return node.Id
}

func CompileLvs(reader io.Reader) trust.LvsModel {
	parser := NewParser(reader)
	lvsFile := parser.parse()
	compiler := NewCompiler(lvsFile)
	return compiler.compile()
}
