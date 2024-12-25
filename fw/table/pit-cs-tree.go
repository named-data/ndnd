package table

import (
	"math/rand"
	"sync"
	"time"

	"github.com/named-data/ndnd/fw/core"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	pq "github.com/named-data/ndnd/std/utils/priority_queue"
)

const expiredPitTickerInterval = 100 * time.Millisecond

type OnPitExpiration func(PitEntry)

var nameTreePitEntryPool = sync.Pool{
	New: func() interface{} {
		entry := new(nameTreePitEntry)
		entry.inRecords = make(map[uint64]*PitInRecord)
		entry.outRecords = make(map[uint64]*PitOutRecord)
		return entry
	},
}

var pitCsTreeNodePool = sync.Pool{
	New: func() interface{} {
		node := new(pitCsTreeNode)
		node.children = make(map[uint64]*pitCsTreeNode)
		node.pitEntries = make([]*nameTreePitEntry, 0, 1)
		return node
	},
}

// PitCsTree represents a PIT-CS implementation that uses a name tree
type PitCsTree struct {
	basePitCsTable

	root *pitCsTreeNode

	nPitEntries int
	pitTokenMap map[uint32]*nameTreePitEntry

	nCsEntries    int
	csReplacement CsReplacementPolicy
	csMap         map[uint64]*nameTreeCsEntry

	pitExpiryQueue pq.Queue[*nameTreePitEntry, int64]
	updateTimer    chan struct{}
	onExpiration   OnPitExpiration
}

type nameTreePitEntry struct {
	basePitEntry                                    // compose with BasePitEntry
	pitCsTable   *PitCsTree                         // pointer to tree
	node         *pitCsTreeNode                     // the tree node associated with this entry
	pqItem       *pq.Item[*nameTreePitEntry, int64] // entry in the expiring queue
}

type nameTreeCsEntry struct {
	baseCsEntry                // compose with BasePitEntry
	node        *pitCsTreeNode // the tree node associated with this entry
}

// pitCsTreeNode represents an entry in a PIT-CS tree.
type pitCsTreeNode struct {
	component *enc.Component
	depth     int

	parent   *pitCsTreeNode
	children map[uint64]*pitCsTreeNode

	pitEntries []*nameTreePitEntry

	csEntry *nameTreeCsEntry
}

// NewPitCS creates a new combined PIT-CS for a forwarding thread.
func NewPitCS(onExpiration OnPitExpiration) *PitCsTree {
	pitCs := new(PitCsTree)
	pitCs.root = new(pitCsTreeNode)
	pitCs.root.component = nil // Root component will be nil since it represents zero components
	pitCs.root.pitEntries = make([]*nameTreePitEntry, 0)
	pitCs.root.children = make(map[uint64]*pitCsTreeNode)
	pitCs.onExpiration = onExpiration
	pitCs.pitTokenMap = make(map[uint32]*nameTreePitEntry)
	pitCs.pitExpiryQueue = pq.New[*nameTreePitEntry, int64]()
	pitCs.updateTimer = make(chan struct{})

	// This value has already been validated from loading the configuration,
	// so we know it will be one of the following (or else fatal)
	switch csReplacementPolicy {
	case "lru":
		pitCs.csReplacement = NewCsLRU(pitCs)
	default:
		core.LogFatal(pitCs, "Unknown CS replacement policy ", csReplacementPolicy)
	}
	pitCs.csMap = make(map[uint64]*nameTreeCsEntry)

	// Schedule first signal
	time.AfterFunc(expiredPitTickerInterval, func() {
		pitCs.updateTimer <- struct{}{}
	})

	return pitCs
}

func (p *PitCsTree) UpdateTimer() <-chan struct{} {
	return p.updateTimer
}

func (p *PitCsTree) Update() {
	for p.pitExpiryQueue.Len() > 0 && p.pitExpiryQueue.PeekPriority() <= time.Now().UnixNano() {
		entry := p.pitExpiryQueue.Pop()
		entry.pqItem = nil
		p.onExpiration(entry)
		p.RemoveInterest(entry)
	}
	if !core.ShouldQuit {
		updateDuration := expiredPitTickerInterval
		if p.pitExpiryQueue.Len() > 0 {
			sleepTime := time.Duration(p.pitExpiryQueue.PeekPriority()-time.Now().UnixNano()) * time.Nanosecond
			if sleepTime > 0 {
				if sleepTime > expiredPitTickerInterval {
					sleepTime = expiredPitTickerInterval
				}
				updateDuration = sleepTime
			}
		}
		// Schedule next signal
		time.AfterFunc(updateDuration, func() {
			p.updateTimer <- struct{}{}
		})
	}
}

func (p *PitCsTree) updatePitExpiry(pitEntry PitEntry) {
	e := pitEntry.(*nameTreePitEntry)
	if e.pqItem == nil {
		e.pqItem = p.pitExpiryQueue.Push(e, e.expirationTime.UnixNano())
	} else {
		p.pitExpiryQueue.Update(e.pqItem, e, e.expirationTime.UnixNano())
	}
}

func (e *nameTreePitEntry) PitCs() PitCsTable {
	return e.pitCsTable
}

// InsertInterest inserts an entry in the PIT upon receipt of an Interest.
// Returns tuple of PIT entry and whether the Nonce is a duplicate.
func (p *PitCsTree) InsertInterest(interest ndn.Interest, hint enc.Name, inFace uint64) (PitEntry, bool) {
	name := interest.Name().Clone()

	node := p.root.fillTreeToPrefixEnc(name)
	var entry *nameTreePitEntry
	for _, curEntry := range node.pitEntries {
		if curEntry.CanBePrefix() == interest.CanBePrefix() &&
			curEntry.MustBeFresh() == interest.MustBeFresh() &&
			((hint == nil && curEntry.ForwardingHintNew() == nil) || hint.Equal(curEntry.ForwardingHintNew())) {
			entry = curEntry
			break
		}
	}

	if entry == nil {
		p.nPitEntries++
		entry = nameTreePitEntryPool.Get().(*nameTreePitEntry)
		entry.node = node
		entry.pitCsTable = p
		entry.encname = name
		entry.canBePrefix = interest.CanBePrefix()
		entry.mustBeFresh = interest.MustBeFresh()
		entry.forwardingHintNew = hint
		clear(entry.inRecords)
		clear(entry.outRecords)
		entry.satisfied = false
		entry.token = p.generateNewPitToken()
		entry.pqItem = nil
		node.pitEntries = append(node.pitEntries, entry)
		p.pitTokenMap[entry.token] = entry
	}

	// Only considered a duplicate (loop) if from different face since
	// is just retransmission and not loop if same face
	for face, inRecord := range entry.inRecords {
		if face != inFace && inRecord.LatestNonce == *interest.Nonce() {
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
			if len(e.node.pitEntries) == 0 {
				entry.node.pruneIfEmpty()
			}
			p.nPitEntries--
			delete(p.pitTokenMap, e.token)
			nameTreePitEntryPool.Put(e)
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
func (p *PitCsTree) FindInterestExactMatchEnc(interest ndn.Interest) PitEntry {
	node := p.root.findExactMatchEntryEnc(interest.Name())
	if node != nil {
		for _, curEntry := range node.pitEntries {
			if curEntry.CanBePrefix() == interest.CanBePrefix() &&
				curEntry.MustBeFresh() == interest.MustBeFresh() {
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
func (p *PitCsTree) FindInterestPrefixMatchByDataEnc(data ndn.Data, token *uint32) []PitEntry {
	if token != nil {
		if entry, ok := p.pitTokenMap[*token]; ok && entry.Token() == *token {
			return []PitEntry{entry}
		}
		return nil
	}
	return p.findInterestPrefixMatchByNameEnc(data.Name())
}

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
	return p.nPitEntries
}

// CsSize returns the number of entries in the CS.
func (p *PitCsTree) CsSize() int {
	return p.nCsEntries
}

// IsCsAdmitting returns whether the CS is admitting content.
func (p *PitCsTree) IsCsAdmitting() bool {
	return csAdmit
}

// IsCsServing returns whether the CS is serving content.
func (p *PitCsTree) IsCsServing() bool {
	return csServe
}

// InsertOutRecord inserts an outrecord for the given interest, updating the
// preexisting one if it already occcurs.
func (e *nameTreePitEntry) InsertOutRecord(interest ndn.Interest, face uint64) *PitOutRecord {
	lifetime := time.Millisecond * 4000
	if interest.Lifetime() != nil {
		lifetime = *interest.Lifetime()
	}

	var record *PitOutRecord
	var ok bool
	if record, ok = e.outRecords[face]; !ok {
		record := new(PitOutRecord)
		record.Face = face
		record.LatestNonce = *interest.Nonce()
		record.LatestTimestamp = time.Now()
		record.ExpirationTime = time.Now().Add(lifetime)
		e.outRecords[face] = record
		return record
	}

	// Existing record
	record.LatestNonce = *interest.Nonce()
	record.LatestTimestamp = time.Now()
	record.ExpirationTime = time.Now().Add(lifetime)
	return record
}

// GetOutRecords returns all outrecords for the given PIT entry.
func (e *nameTreePitEntry) GetOutRecords() []*PitOutRecord {
	records := make([]*PitOutRecord, 0)
	for _, value := range e.outRecords {
		records = append(records, value)
	}
	return records
}

func At(n enc.Name, index int) enc.Component {
	if index < -len(n) || index >= len(n) {
		return enc.Component{}
	}

	if index < 0 {
		return n[len(n)+index]
	}
	return n[index]
}

func (p *pitCsTreeNode) findExactMatchEntryEnc(name enc.Name) *pitCsTreeNode {
	if len(name) > p.depth {
		comp := At(name, p.depth)
		if child, ok := p.children[comp.Hash()]; ok {
			return child.findExactMatchEntryEnc(name)
		}
	} else if len(name) == p.depth {
		return p
	}
	return nil
}

func (p *pitCsTreeNode) findLongestPrefixEntryEnc(name enc.Name) *pitCsTreeNode {
	if len(name) > p.depth {
		comp := At(name, p.depth)
		if child, ok := p.children[comp.Hash()]; ok {
			return child.findLongestPrefixEntryEnc(name)
		}
	}
	return p
}

func (p *pitCsTreeNode) fillTreeToPrefixEnc(name enc.Name) *pitCsTreeNode {
	curNode := p.findLongestPrefixEntryEnc(name)
	for depth := curNode.depth + 1; depth <= len(name); depth++ {
		comp := At(name, depth-1)

		newNode := pitCsTreeNodePool.Get().(*pitCsTreeNode)
		newNode.component = &comp
		newNode.depth = depth
		newNode.parent = curNode
		clear(newNode.children)
		clear(newNode.pitEntries)
		curNode.children[comp.Hash()] = newNode
		curNode = newNode
	}
	return curNode
}

func (p *pitCsTreeNode) getChildrenCount() int {
	return len(p.children)
}

func (p *pitCsTreeNode) pruneIfEmpty() {
	for curNode := p; curNode.parent != nil && curNode.getChildrenCount() == 0 &&
		len(curNode.pitEntries) == 0 && curNode.csEntry == nil; curNode = curNode.parent {
		delete(curNode.parent.children, curNode.component.Hash())
		pitCsTreeNodePool.Put(curNode)
	}
}

func (p *PitCsTree) generateNewPitToken() uint32 {
	for {
		token := rand.Uint32()
		if _, ok := p.pitTokenMap[token]; !ok {
			return token
		}
	}
}

// FindMatchingDataFromCS finds the best matching entry in the CS (if any).
// If MustBeFresh is set to true in the Interest, only non-stale CS entries
// will be returned.
func (p *PitCsTree) FindMatchingDataFromCS(interest ndn.Interest) CsEntry {
	node := p.root.findExactMatchEntryEnc(interest.Name())
	if node != nil {
		if !interest.CanBePrefix() {
			if node.csEntry != nil &&
				(!interest.MustBeFresh() || time.Now().Before(node.csEntry.staleTime)) {
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
func (p *PitCsTree) InsertData(data ndn.Data, wire []byte) {
	dataName := data.Name()
	index := dataName.Hash()
	staleTime := time.Now()
	if data.Freshness() != nil {
		staleTime = staleTime.Add(*data.Freshness())
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
		p.nCsEntries++
		node := p.root.fillTreeToPrefixEnc(data.Name())
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
		p.nCsEntries--
	}
}

// Given a pitCsTreeNode that is the longest prefix match of an interest, look for any
// CS data rechable from this pitCsTreeNode. This function must be called only after
// the interest as far as possible with the nodes components in the PitCSTree.
// For example, if we have data for /a/b/v=10 and the interest is /a/b,
// p should be the `b` node, not the root node.
func (p *pitCsTreeNode) findMatchingDataCSPrefix(interest ndn.Interest) CsEntry {
	if p.csEntry != nil && (!interest.MustBeFresh() || time.Now().Before(p.csEntry.staleTime)) {
		// A csEntry exists at this node and is acceptable to satisfy the interest
		return p.csEntry
	}

	// No csEntry at current node, look farther down the tree
	// We must have already matched the entire interest name
	if p.depth >= len(interest.Name()) {
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
