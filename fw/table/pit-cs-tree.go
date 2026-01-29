package table

import (
	"sync/atomic"
	"time"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/priority_queue"
)

const expiredPitTickerInterval = 200 * time.Millisecond
const pitTokenLookupTableSize = 125000 // 1MB

type OnPitExpiration func(PitEntry)

// PitCsTree represents a PIT-CS implementation that uses a name tree
type PitCsTree struct {
	root *pitCsTreeNode

	nPitEntries atomic.Int64

	nPitToken uint64
	pitTokens []*nameTreePitEntry

	nCsEntries    atomic.Int64
	csReplacement CsReplacementPolicy
	csMap         map[uint64]*nameTreeCsEntry

	pitExpiryQueue priority_queue.Queue[*nameTreePitEntry, int64]
	updateTicker   *time.Ticker
	onExpiration   OnPitExpiration
}

type nameTreePitEntry struct {
	basePitEntry                                                // compose with BasePitEntry
	pitCsTable   *PitCsTree                                     // pointer to tree
	node         *pitCsTreeNode                                 // the tree node associated with this entry
	pqItem       *priority_queue.Item[*nameTreePitEntry, int64] // entry in the expiring queue
}

type nameTreeCsEntry struct {
	baseCsEntry                // compose with BasePitEntry
	node        *pitCsTreeNode // the tree node associated with this entry
}

// pitCsTreeNode represents an entry in a PIT-CS tree.
type pitCsTreeNode struct {
	component enc.Component
	name      enc.Name
	depth     int

	parent   *pitCsTreeNode
	children map[uint64]*pitCsTreeNode

	pitEntries []*nameTreePitEntry

	csEntry *nameTreeCsEntry
}

// NewPitCS creates a new combined PIT-CS for a forwarding thread.
func NewPitCS(onExpiration OnPitExpiration) *PitCsTree {
	pitCs := new(PitCsTree)
	pitCs.root = PitCsPools.PitCsTreeNode.New()
	pitCs.root.component = enc.Component{} // zero component
	pitCs.onExpiration = onExpiration
	pitCs.pitTokens = make([]*nameTreePitEntry, pitTokenLookupTableSize)
	pitCs.pitExpiryQueue = priority_queue.New[*nameTreePitEntry, int64]()
	pitCs.updateTicker = time.NewTicker(expiredPitTickerInterval)

	// This value has already been validated from loading the configuration,
	// so we know it will be one of the following (or else fatal)
	switch CfgCsReplacementPolicy() {
	case "lru":
		pitCs.csReplacement = NewCsLRU(pitCs)
	default:
		core.Log.Fatal(nil, "Unknown CS replacement policy", "policy", CfgCsReplacementPolicy())
	}
	pitCs.csMap = make(map[uint64]*nameTreeCsEntry)

	return pitCs
}

// (AI GENERATED DESCRIPTION): Returns the channel that emits time events whenever the PIT‑CS tree’s internal update ticker fires.
func (p *PitCsTree) UpdateTicker() <-chan time.Time {
	return p.updateTicker.C
}

// (AI GENERATED DESCRIPTION): Expires all pending PIT entries whose timers have elapsed, invoking their expiration callbacks and removing them from the PIT.
func (p *PitCsTree) Update() {
	for p.pitExpiryQueue.Len() > 0 && p.pitExpiryQueue.PeekPriority() <= time.Now().UnixNano() {
		entry := p.pitExpiryQueue.Pop()
		entry.pqItem = nil
		p.onExpiration(entry)
		p.RemoveInterest(entry)
	}
}

// (AI GENERATED DESCRIPTION): Updates or inserts the given PIT entry into the expiration priority queue, setting its priority to the entry’s expiration time.
func (p *PitCsTree) updatePitExpiry(pitEntry PitEntry) {
	e := pitEntry.(*nameTreePitEntry)
	if e.pqItem == nil {
		e.pqItem = p.pitExpiryQueue.Push(e, e.expirationTime.UnixNano())
	} else {
		p.pitExpiryQueue.Update(e.pqItem, e, e.expirationTime.UnixNano())
	}
}

// (AI GENERATED DESCRIPTION): Returns the PitCsTable associated with this nameTreePitEntry.
func (e *nameTreePitEntry) PitCs() PitCsTable {
	return e.pitCsTable
}

// InsertInterest inserts an entry in the PIT upon receipt of an Interest.
// Returns tuple of PIT entry and whether the Nonce is a duplicate.
func (p *PitCsTree) InsertInterest(interest *defn.FwInterest, hint enc.Name, inFace uint64) (PitEntry, bool) {
	name := interest.Name()

	node := p.root.fillTreeToPrefixEnc(name)
	var entry *nameTreePitEntry
	for _, curEntry := range node.pitEntries {
		if curEntry.CanBePrefix() == interest.CanBePrefixV &&
			curEntry.MustBeFresh() == interest.MustBeFreshV &&
			((hint == nil && curEntry.ForwardingHintNew() == nil) || hint.Equal(curEntry.ForwardingHintNew())) {
			entry = curEntry
			break
		}
	}

	if entry == nil {
		p.nPitEntries.Add(1)
		entry = PitCsPools.NameTreePitEntry.Get()
		entry.node = node
		entry.pitCsTable = p
		entry.encname = node.name
		entry.canBePrefix = interest.CanBePrefixV
		entry.mustBeFresh = interest.MustBeFreshV
		entry.forwardingHintNew = hint
		entry.satisfied = false
		node.pitEntries = append(node.pitEntries, entry)
		entry.token = p.newPitToken()
		entry.pqItem = nil

		tokIdx := p.pitTokenIdx(entry.token)
		p.pitTokens[tokIdx] = entry
	}

	// Only considered a duplicate (loop) if from different face since
	// is just retransmission and not loop if same face
	for face, inRecord := range entry.inRecords {
		if face != inFace && inRecord.LatestNonce == interest.NonceV.Unwrap() {
			return entry, true
		}
	}

	// Cancel expiration time
	entry.expirationTime = time.Unix(0, 0)

	return entry, false
}

// RemoveInterest removes the specified PIT entry, returning true if the entry
// was removed and false if was not (because it does not exist).
func (p *PitCsTree) RemoveInterest(pitEntry PitEntry) bool {
	e := pitEntry.(*nameTreePitEntry) // No error check needed because PitCsTree always uses nameTreePitEntry
	for i, entry := range e.node.pitEntries {
		if entry == pitEntry {
			if len(e.node.pitEntries) > 1 {
				e.node.pitEntries[i] = e.node.pitEntries[len(e.node.pitEntries)-1]
			}
			e.node.pitEntries = e.node.pitEntries[:len(e.node.pitEntries)-1]
			entry.node.pruneIfEmpty()
			p.nPitEntries.Add(-1)

			// remove entry from pit token lookup table
			tokIdx := p.pitTokenIdx(entry.Token())
			if p.pitTokens[tokIdx] == entry {
				p.pitTokens[tokIdx] = nil
			}

			// now it is invalid to use the entry
			entry.encname = nil // invalidate
			entry.pitCsTable = nil
			entry.node = nil
			pitEntry.ClearInRecords()  // pool
			pitEntry.ClearOutRecords() // pool
			PitCsPools.NameTreePitEntry.Put(entry)
			return true
		}
	}
	return false
}

// FindInterestExactMatch returns the PIT entry for an exact match of the
// given interest.

// FindInterestPrefixMatchByData returns all interests that could be satisfied
// by the given data.
// Example: If we have interests /a and /a/b, a prefix search for data with name /a/b
// will return PitEntries for both /a and /a/b
func (p *PitCsTree) FindInterestExactMatchEnc(interest *defn.FwInterest) PitEntry {
	node := p.root.findExactMatchEntryEnc(interest.NameV)
	if node != nil {
		for _, curEntry := range node.pitEntries {
			if curEntry.CanBePrefix() == interest.CanBePrefixV &&
				curEntry.MustBeFresh() == interest.MustBeFreshV {
				return curEntry
			}
		}
	}
	return nil
}

// FindInterestPrefixMatchByData returns all interests that could be satisfied
// by the given data.
// Example: If we have interests /a and /a/b, a prefix search for data with name /a/b
// will return PitEntries for both /a and /a/b
func (p *PitCsTree) FindInterestPrefixMatchByDataEnc(data *defn.FwData, token *uint32) []PitEntry {
	if token != nil {
		entry := p.pitTokens[p.pitTokenIdx(*token)]
		if entry != nil && entry.encname != nil && entry.Token() == *token {
			return []PitEntry{entry}
		}
	}
	return p.findInterestPrefixMatchByNameEnc(data.NameV)
}

// (AI GENERATED DESCRIPTION): Returns all PIT entries that match the given name either as a prefix or exactly, by starting at the deepest node that matches the name’s prefix and walking up to the root.
func (p *PitCsTree) findInterestPrefixMatchByNameEnc(name enc.Name) []PitEntry {
	matching := make([]PitEntry, 0)
	dataNameLen := len(name)
	for curNode := p.root.findLongestPrefixEntryEnc(name); curNode != nil; curNode = curNode.parent {
		for _, entry := range curNode.pitEntries {
			if entry.canBePrefix || curNode.depth == dataNameLen {
				matching = append(matching, entry)
			}
		}
	}
	return matching
}

// PitSize returns the number of entries in the PIT.
func (p *PitCsTree) PitSize() int {
	return int(p.nPitEntries.Load())
}

// CsSize returns the number of entries in the CS.
func (p *PitCsTree) CsSize() int {
	return int(p.nCsEntries.Load())
}

// IsCsAdmitting returns whether the CS is admitting content.
func (p *PitCsTree) IsCsAdmitting() bool {
	return CfgCsAdmit()
}

// IsCsServing returns whether the CS is serving content.
func (p *PitCsTree) IsCsServing() bool {
	return CfgCsServe()
}

// (AI GENERATED DESCRIPTION): Returns the component at the specified index of the name (negative indices count from the end) or an empty component if the index is out of bounds.
func At(n enc.Name, index int) enc.Component {
	if index < -len(n) || index >= len(n) {
		return enc.Component{}
	}

	if index < 0 {
		return n[len(n)+index]
	}
	return n[index]
}

// (AI GENERATED DESCRIPTION): Recursively traverses a PIT/CS tree to locate and return the node whose encoded name exactly matches the supplied name, or nil if no such node exists.
func (p *pitCsTreeNode) findExactMatchEntryEnc(name enc.Name) *pitCsTreeNode {
	if len(name) > p.depth {
		if child, ok := p.children[At(name, p.depth).Hash()]; ok {
			return child.findExactMatchEntryEnc(name)
		}
	} else if len(name) == p.depth {
		return p
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Finds and returns the deepest pitCsTreeNode in the PIT‑CS tree that matches the longest prefix of the supplied name.
func (p *pitCsTreeNode) findLongestPrefixEntryEnc(name enc.Name) *pitCsTreeNode {
	if len(name) > p.depth {
		if child, ok := p.children[At(name, p.depth).Hash()]; ok {
			return child.findLongestPrefixEntryEnc(name)
		}
	}
	return p
}

// (AI GENERATED DESCRIPTION): Extends the PIT/CS tree from the longest existing prefix to the full encoded name by creating any missing intermediate nodes, and returns the leaf node representing that name.
func (p *pitCsTreeNode) fillTreeToPrefixEnc(name enc.Name) *pitCsTreeNode {
	entry := p.findLongestPrefixEntryEnc(name)

	for depth := entry.depth; depth < len(name); depth++ {
		component := At(name, depth).Clone()

		child := PitCsPools.PitCsTreeNode.Get()
		child.name = entry.name.Append(component)
		child.depth = depth + 1
		child.component = component
		child.parent = entry

		entry.children[component.Hash()] = child
		entry = child
	}
	return entry
}

// (AI GENERATED DESCRIPTION): Returns the number of child nodes currently stored in the PIT‑CS tree node.
func (p *pitCsTreeNode) getChildrenCount() int {
	return len(p.children)
}

// (AI GENERATED DESCRIPTION): Removes empty leaf nodes from the PIT/CS tree by climbing upward from the current node, deleting each node that has no children, PIT entries, or CS entry, and returning the pruned nodes to the pool.
func (p *pitCsTreeNode) pruneIfEmpty() {
	for curNode := p; curNode.parent != nil && curNode.getChildrenCount() == 0 &&
		len(curNode.pitEntries) == 0 && curNode.csEntry == nil; curNode = curNode.parent {
		delete(curNode.parent.children, curNode.component.Hash())
		PitCsPools.PitCsTreeNode.Put(curNode)
	}
}

// newPitToken returns a new PIT token.
func (p *PitCsTree) newPitToken() uint32 {
	p.nPitToken++
	return uint32(p.nPitToken)
}

// pitTokenIdx returns the index in the pitTokens table.
func (p *PitCsTree) pitTokenIdx(token uint32) uint32 {
	return token % uint32(len(p.pitTokens))
}

// FindMatchingDataFromCS finds the best matching entry in the CS (if any).
// If MustBeFresh is set to true in the Interest, only non-stale CS entries
// will be returned.
func (p *PitCsTree) FindMatchingDataFromCS(interest *defn.FwInterest) CsEntry {
	node := p.root.findExactMatchEntryEnc(interest.NameV)
	if node != nil {
		if !interest.CanBePrefixV {
			if node.csEntry != nil &&
				(!interest.MustBeFreshV || time.Now().Before(node.csEntry.staleTime)) {
				p.csReplacement.BeforeUse(node.csEntry.index, node.csEntry.wire)
				return node.csEntry
			}
			// Return nil instead of node.csEntry so that
			// the return type is nil rather than CSEntry{nil}
			return nil
		}
		return node.findMatchingDataCSPrefix(interest)
	}
	return nil
}

// InsertData inserts a Data packet into the Content Store.
func (p *PitCsTree) InsertData(data *defn.FwData, wire []byte) {
	index := data.NameV.Hash()
	staleTime := time.Now()
	if data.MetaInfo != nil && data.MetaInfo.FreshnessPeriod.IsSet() {
		staleTime = staleTime.Add(data.MetaInfo.FreshnessPeriod.Unwrap())
	}

	store := make([]byte, len(wire))
	copy(store, wire)

	if entry, ok := p.csMap[index]; ok {
		// Replace existing entry
		entry.wire = store
		entry.staleTime = staleTime

		p.csReplacement.AfterRefresh(index, wire, data)
	} else {
		// New entry
		p.nCsEntries.Add(1)
		node := p.root.fillTreeToPrefixEnc(data.NameV)
		node.csEntry = &nameTreeCsEntry{
			node: node,
			baseCsEntry: baseCsEntry{
				index:     index,
				wire:      store,
				staleTime: staleTime,
			},
		}

		p.csMap[index] = node.csEntry
		p.csReplacement.AfterInsert(index, wire, data)

		// Tell replacement strategy to evict entries if needed
		p.csReplacement.EvictEntries()
	}
}

// eraseCsDataFromReplacementStrategy allows the replacement strategy to
// erase the data with the specified name from the Content Store.
func (p *PitCsTree) eraseCsDataFromReplacementStrategy(index uint64) {
	if entry, ok := p.csMap[index]; ok {
		entry.node.csEntry = nil
		delete(p.csMap, index)
		p.nCsEntries.Add(-1)
	}
}

// Given a pitCsTreeNode that is the longest prefix match of an interest, look for any
// CS data rechable from this pitCsTreeNode. This function must be called only after
// the interest as far as possible with the nodes components in the PitCSTree.
// For example, if we have data for /a/b/v=10 and the interest is /a/b,
// p should be the `b` node, not the root node.
func (p *pitCsTreeNode) findMatchingDataCSPrefix(interest *defn.FwInterest) CsEntry {
	if p.csEntry != nil && (!interest.MustBeFreshV || time.Now().Before(p.csEntry.staleTime)) {
		// A csEntry exists at this node and is acceptable to satisfy the interest
		return p.csEntry
	}

	// No csEntry at current node, look farther down the tree
	// We must have already matched the entire interest name
	if p.depth >= len(interest.NameV) {
		for _, child := range p.children {
			potentialMatch := child.findMatchingDataCSPrefix(interest)
			if potentialMatch != nil {
				return potentialMatch
			}
		}
	}

	// If found none, then return
	return nil
}
