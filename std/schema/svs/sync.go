package svs

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v2"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/utils"
)

type SyncState int

type MissingData struct {
	Name     enc.Name
	StartSeq uint64
	EndSeq   uint64
}

const (
	SyncSteady SyncState = iota
	SyncSuppression
)

// SvsNode implements the StateVectorSync but works for only one instance.
// Similar is RegisterPolicy. A better implementation is needed if there is
// a need that multiple producers under the same name pattern that runs on the same application instance.
// It would also be more natural if we make 1-1 mapping between MatchedNodes and SVS instances,
// instead of the Node and the SVS instance, which is against the philosophy of matching.
// Also, this sample always starts from sequence number 0.
type SvsNode struct {
	schema.BaseNodeImpl

	OnMissingData *schema.EventTarget

	SyncInterval        time.Duration
	SuppressionInterval time.Duration
	BaseMatching        enc.Matching
	ChannelSize         uint64
	SelfName            enc.Name

	dataLock        sync.Mutex
	timer           ndn.Timer
	cancelSyncTimer func() error
	missChan        chan MissingData
	stopChan        chan struct{}

	localSv   spec_svs.StateVector
	aggSv     spec_svs.StateVector
	state     SyncState
	selfSeq   uint64
	ownPrefix enc.Name
	notifNode *schema.Node
}

// (AI GENERATED DESCRIPTION): Returns a constant string “svs-node” as the string representation of an SvsNode.
func (n *SvsNode) String() string {
	return "svs-node"
}

// (AI GENERATED DESCRIPTION): Returns the SvsNode instance as a schema.NodeImpl.
func (n *SvsNode) NodeImplTrait() schema.NodeImpl {
	return n
}

// (AI GENERATED DESCRIPTION): Creates and configures an SvsNode, establishing a leaf node for data items and a notification express point with specified matching rules, lifetimes, and attaching event listeners.
func CreateSvsNode(node *schema.Node) schema.NodeImpl {
	ret := &SvsNode{
		BaseNodeImpl: schema.BaseNodeImpl{
			Node:        node,
			OnAttachEvt: &schema.EventTarget{},
			OnDetachEvt: &schema.EventTarget{},
		},
		OnMissingData:       &schema.EventTarget{},
		BaseMatching:        enc.Matching{},
		SyncInterval:        30 * time.Second,
		SuppressionInterval: 200 * time.Millisecond,
	}

	path, _ := enc.NamePatternFromStr("/<8=nodeId>/<seq=seqNo>")
	leafNode := node.PutNode(path, schema.LeafNodeDesc)
	leafNode.Set(schema.PropCanBePrefix, false)
	leafNode.Set(schema.PropMustBeFresh, false)
	leafNode.Set(schema.PropLifetime, 4*time.Second)
	leafNode.Set(schema.PropFreshness, 60*time.Second)
	leafNode.Set("ValidDuration", 876000*time.Hour)

	path, _ = enc.NamePatternFromStr("/32=notif")
	ret.notifNode = node.PutNode(path, schema.ExpressPointDesc)
	ret.notifNode.Set(schema.PropCanBePrefix, true)
	ret.notifNode.Set(schema.PropMustBeFresh, true)
	ret.notifNode.Set(schema.PropLifetime, 1*time.Second)
	ret.notifNode.AddEventListener(schema.PropOnInterest, utils.IdPtr(ret.onSyncInt))

	ret.BaseMatching = enc.Matching{}
	ret.OnAttachEvt.Add(utils.IdPtr(ret.onAttach))
	ret.OnDetachEvt.Add(utils.IdPtr(ret.onDetach))

	return ret
}

// (AI GENERATED DESCRIPTION): Finds the index of an entry with the given name in a StateVector, returning –1 if no match is found.
func findSvsEntry(v *spec_svs.StateVector, name enc.Name) int {
	// This is less efficient but enough for a demo.
	for i, n := range v.Entries {
		if name.Equal(n.Name) {
			return i
		}
	}
	return -1
}

// (AI GENERATED DESCRIPTION): Handles an incoming state‑vector sync interest by parsing the vector, updating the local vector, requesting any missing data, flagging outdated entries, and adjusting the node’s sync state and timers as needed.
func (n *SvsNode) onSyncInt(event *schema.Event) any {
	remoteSv, err := spec_svs.ParseStateVector(enc.NewWireView(event.Content), true)
	if err != nil {
		log.Error(n, "Unable to parse state vector - DROP", "err", err)
	}

	// If append() is called on localSv slice, a lock is necessary
	n.dataLock.Lock()
	defer n.dataLock.Unlock()

	// Compare state vectors
	// needFetch := false
	needNotif := false
	for _, cur := range remoteSv.Entries {
		li := findSvsEntry(&n.localSv, cur.Name)
		if li == -1 {
			n.localSv.Entries = append(n.localSv.Entries, &spec_svs.StateVectorEntry{
				Name:  cur.Name,
				SeqNo: cur.SeqNo,
			})
			// needFetch = true
			n.missChan <- MissingData{
				Name:     cur.Name,
				StartSeq: 1,
				EndSeq:   cur.SeqNo + 1,
			}
		} else if n.localSv.Entries[li].SeqNo < cur.SeqNo {
			log.Debug(n, "Missing data found", "name", cur.Name, "local", n.localSv.Entries[li].SeqNo, "cur", cur.SeqNo)
			n.missChan <- MissingData{
				Name:     cur.Name,
				StartSeq: n.localSv.Entries[li].SeqNo + 1,
				EndSeq:   cur.SeqNo + 1,
			}
			n.localSv.Entries[li].SeqNo = cur.SeqNo
			// needFetch = true
		} else if n.localSv.Entries[li].SeqNo > cur.SeqNo {
			log.Debug(n, "Outdated remote on", "name", cur.Name, "local", n.localSv.Entries[li].SeqNo, "cur", cur.SeqNo)
			needNotif = true
		}
	}
	for _, cur := range n.localSv.Entries {
		li := findSvsEntry(remoteSv, cur.Name)
		if li == -1 {
			needNotif = true
		}
	}
	// Notify the callback coroutine if applicable
	// if needFetch {
	// 	select {
	// 	case n.sigChan <- struct{}{}:
	// 	default:
	// 	}
	// }
	// Set sync state if applicable
	// if needNotif {
	// 	n.aggregate(remoteSv)
	// 	if n.state == SyncSteady {
	// 		n.transitToSuppress(remoteSv)
	// 	}
	// }
	// TODO: Have trouble understanding this mechanism from the Spec.
	// From StateVectorSync Spec 4.4,
	// "Incoming Sync Interest is outdated: Node moves to Suppression State."
	// implies the state becomes Suppression State when `remote any< local`
	// From StateVectorSync Spec 6, the box below
	// "local_state_vector any< x"
	// implies the state becomes Suppression State when `local any< remote`
	// Contradiction. The wrong one should be the figure.
	// Since suppression is an optimization that does not affect the demo, ignore for now.
	// Report this issue to the team when have time.

	if needNotif || n.state == SyncSuppression {
		// Set the aggregation timer
		if n.state == SyncSteady {
			n.state = SyncSuppression
			n.aggSv = spec_svs.StateVector{Entries: make([]*spec_svs.StateVectorEntry, len(remoteSv.Entries))}
			copy(n.aggSv.Entries, remoteSv.Entries)
			n.cancelSyncTimer()
			n.cancelSyncTimer = n.timer.Schedule(n.getAggIntv(), n.onSyncTimer)
		} else {
			// Should aggregate the incoming sv first, and only shoot after sync timer.
			n.aggregate(remoteSv)
		}
	} else {
		// Reset the sync timer (already in lock)
		n.cancelSyncTimer()
		n.cancelSyncTimer = n.timer.Schedule(n.getSyncIntv(), n.onSyncTimer)
	}

	return true
}

// (AI GENERATED DESCRIPTION): Provides direct access to the node’s `MissingData` channel, which emits notifications of missing data (use this channel rather than the OnMissingData callback).
func (n *SvsNode) MissingDataChannel() chan MissingData {
	// Note: DO NOT use with OnMissingData
	return n.missChan
}

// (AI GENERATED DESCRIPTION): Returns the node’s current sequence number.
func (n *SvsNode) MySequence() uint64 {
	return n.selfSeq
}

// (AI GENERATED DESCRIPTION): Aggregates a remote state vector into the node’s aggregate state vector, adding new entries or updating existing ones to the highest sequence number seen.
func (n *SvsNode) aggregate(remoteSv *spec_svs.StateVector) {
	for _, cur := range remoteSv.Entries {
		li := findSvsEntry(&n.aggSv, cur.Name)
		if li == -1 {
			n.aggSv.Entries = append(n.aggSv.Entries, &spec_svs.StateVectorEntry{
				Name:  cur.Name,
				SeqNo: cur.SeqNo,
			})
		} else {
			n.aggSv.Entries[li].SeqNo = max(n.aggSv.Entries[li].SeqNo, cur.SeqNo)
		}
	}
}

// (AI GENERATED DESCRIPTION): Handles the periodic sync timer by suppressing redundant state‑vector transmissions when the local vector is already covered by the aggregated vector, otherwise expressing a new state vector, and then rescheduling the next timer.
func (n *SvsNode) onSyncTimer() {
	n.dataLock.Lock()
	defer n.dataLock.Unlock()
	// If in suppression state, first test necessity
	notNecessary := false
	if n.state == SyncSuppression {
		n.state = SyncSteady
		notNecessary = true
		for _, cur := range n.localSv.Entries {
			li := findSvsEntry(&n.aggSv, cur.Name)
			if li == -1 || n.aggSv.Entries[li].SeqNo < cur.SeqNo {
				notNecessary = false
				break
			}
		}
	}
	if !notNecessary {
		n.expressStateVec()
	}
	// In case a new one is just scheduled by the onInterest callback. No-op most of the case.
	n.cancelSyncTimer()
	n.cancelSyncTimer = n.timer.Schedule(n.getSyncIntv(), n.onSyncTimer)
}

// (AI GENERATED DESCRIPTION): Sends the node’s current state vector to the notification node by calling the "NeedChan" event with the encoded state vector.
func (n *SvsNode) expressStateVec() {
	n.notifNode.Apply(n.BaseMatching).Call("NeedChan", n.localSv.Encode())
}

// (AI GENERATED DESCRIPTION): Returns a slightly randomized sync interval by adding a random deviation (up to roughly one‑eighth of the configured SyncInterval) to the node’s base sync interval.
func (n *SvsNode) getSyncIntv() time.Duration {
	dev := rand.Int63n(n.SyncInterval.Nanoseconds()/4) - n.SyncInterval.Nanoseconds()/8
	return n.SyncInterval + time.Duration(dev)*time.Nanosecond
}

// (AI GENERATED DESCRIPTION): Computes a randomized aggregation interval by offsetting the node’s `SuppressionInterval` with a random value in the range [−½ × SuppressionInterval, +½ × SuppressionInterval].
func (n *SvsNode) getAggIntv() time.Duration {
	dev := rand.Int63n(n.SuppressionInterval.Nanoseconds()) - n.SuppressionInterval.Nanoseconds()/2
	return n.SuppressionInterval + time.Duration(dev)*time.Nanosecond
}

// (AI GENERATED DESCRIPTION): Creates a new Data packet with an incremented sequence number, updates the node’s local state vector, and broadcasts the state vector, returning the encoded packet (or empty if the provide operation fails).
func (n *SvsNode) NewData(mNode schema.MatchedNode, content enc.Wire) enc.Wire {
	n.dataLock.Lock()
	defer n.dataLock.Unlock()

	n.selfSeq++
	newDataName := make(enc.Name, len(n.ownPrefix)+1)
	copy(newDataName, n.ownPrefix)
	newDataName[len(n.ownPrefix)] = enc.NewSequenceNumComponent(n.selfSeq)
	mLeafNode := mNode.Refine(newDataName)
	ret := mLeafNode.Call("Provide", content).(enc.Wire)
	if len(ret) > 0 {
		li := findSvsEntry(&n.localSv, n.SelfName)
		if li >= 0 {
			n.localSv.Entries[li].SeqNo = n.selfSeq
		}
		n.state = SyncSteady
		log.Debug(n, "NewData generated", "seq", n.selfSeq)
		n.expressStateVec()
	} else {
		log.Error(n, "Failed to provide", "seq", n.selfSeq)
		n.selfSeq--
	}
	return ret
}

// (AI GENERATED DESCRIPTION): Initializes an SvsNode’s configuration, timers, state vectors, and communication channels upon attachment to a schema node, setting up its local state vector entry and starting the synchronization routine.
func (n *SvsNode) onAttach(event *schema.Event) any {
	if n.ChannelSize == 0 || len(n.SelfName) == 0 ||
		n.BaseMatching == nil || n.SyncInterval <= 0 || n.SuppressionInterval <= 0 {
		panic(errors.New("SvsNode: not configured before Init"))
	}

	n.timer = event.TargetNode.Engine().Timer()
	n.dataLock = sync.Mutex{}
	n.dataLock.Lock()
	defer n.dataLock.Unlock()

	n.ownPrefix = event.TargetNode.Apply(n.BaseMatching).Name
	n.ownPrefix = append(n.ownPrefix, n.SelfName...)

	// OnMissingData callback

	n.localSv = spec_svs.StateVector{Entries: make([]*spec_svs.StateVectorEntry, 0)}
	n.aggSv = spec_svs.StateVector{Entries: make([]*spec_svs.StateVectorEntry, 0)}
	// n.onMiss = schema.NewEvent[*SvsOnMissingEvent]()
	n.state = SyncSteady
	n.missChan = make(chan MissingData, n.ChannelSize)
	// The first sync Interest should be sent out ASAP
	n.cancelSyncTimer = n.timer.Schedule(min(n.getSyncIntv(), 100*time.Millisecond), n.onSyncTimer)

	n.stopChan = make(chan struct{}, 1)
	if len(n.OnMissingData.Val()) > 0 {
		go n.callbackRoutine()
	}

	// initialize localSv
	// TODO: this demo does not consider recovery from off-line. Should be done via ENV and storage policy.
	n.localSv.Entries = append(n.localSv.Entries, &spec_svs.StateVectorEntry{
		Name:  n.SelfName,
		SeqNo: 0,
	})
	n.selfSeq = 0
	return nil
}

// (AI GENERATED DESCRIPTION): Detaches the SVS node by stopping its sync timer, closing the miss channel, signaling and closing the stop channel, and releasing the data lock.
func (n *SvsNode) onDetach(event *schema.Event) any {
	n.dataLock.Lock()
	defer n.dataLock.Unlock()
	n.cancelSyncTimer()
	close(n.missChan)
	n.stopChan <- struct{}{}
	close(n.stopChan)
	return nil
}

// (AI GENERATED DESCRIPTION): Runs as a goroutine, repeatedly receiving callbacks from the SvsNode’s callback channel and dispatching each to the appropriate handler.
func (n *SvsNode) callbackRoutine() {
	panic("TODO: TO BE DONE")
}

// (AI GENERATED DESCRIPTION): Generates a full data packet name by extending the matched node’s name with a given generic component followed by a sequence‑number component.
func (n *SvsNode) GetDataName(mNode schema.MatchedNode, name []byte, seq uint64) enc.Name {
	ret := make(enc.Name, len(mNode.Name)+2)
	copy(ret, mNode.Name)
	ret[len(mNode.Name)] = enc.Component{Typ: enc.TypeGenericNameComponent, Val: name}
	ret[len(mNode.Name)+1] = enc.NewSequenceNumComponent(seq)
	return ret
}

// (AI GENERATED DESCRIPTION): Returns the node as either a *SvsNode or its embedded *schema.BaseNodeImpl, or nil if the requested type is not supported.
func (n *SvsNode) CastTo(ptr any) any {
	switch ptr.(type) {
	case (*SvsNode):
		return n
	case (*schema.BaseNodeImpl):
		return &(n.BaseNodeImpl)
	default:
		return nil
	}
}

var SvsNodeDesc *schema.NodeImplDesc

// (AI GENERATED DESCRIPTION): Registers the SvsNode implementation with the schema, defining its properties, events, functions, and constructor.
func init() {
	SvsNodeDesc = &schema.NodeImplDesc{
		ClassName: "SvsNode",
		Properties: map[schema.PropKey]schema.PropertyDesc{
			"SyncInterval":        schema.TimePropertyDesc("SyncInterval"),
			"SuppressionInterval": schema.TimePropertyDesc("SuppressionInterval"),
			"BaseMatching":        schema.MatchingPropertyDesc("BaseMatching"),
			"ChannelSize":         schema.DefaultPropertyDesc("ChannelSize"),
			"SelfName":            schema.DefaultPropertyDesc("SelfName"),
			"ContentType":         schema.SubNodePropertyDesc("/<8=nodeId>/<seq=seqNo>", "ContentType"),
			"Lifetime":            schema.SubNodePropertyDesc("/<8=nodeId>/<seq=seqNo>", "Lifetime"),
			"Freshness":           schema.SubNodePropertyDesc("/<8=nodeId>/<seq=seqNo>", "Freshness"),
			"ValidDuration":       schema.SubNodePropertyDesc("/<8=nodeId>/<seq=seqNo>", "ValidDuration"),
			"MustBeFresh":         schema.SubNodePropertyDesc("/<8=nodeId>/<seq=seqNo>", "MustBeFresh"),
		},
		Events: map[schema.PropKey]schema.EventGetter{
			schema.PropOnAttach: schema.DefaultEventTarget(schema.PropOnAttach),
			schema.PropOnDetach: schema.DefaultEventTarget(schema.PropOnDetach),
			"OnMissingData":     schema.DefaultEventTarget("OnMissingData"),
		},
		Functions: map[string]schema.NodeFunc{
			"NewData": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 1 {
					err := fmt.Errorf("SvsNode.NewData requires 1 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				content, ok := args[0].(enc.Wire)
				if !ok && args[0] != nil {
					err := ndn.ErrInvalidValue{Item: "content", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*SvsNode](mNode.Node).NewData(mNode, content)
			},
			"MissingDataChannel": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 0 {
					err := fmt.Errorf("SvsNode.MissingDataChannel requires 0 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*SvsNode](mNode.Node).MissingDataChannel()
			},
			"MySequence": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 0 {
					err := fmt.Errorf("SvsNode.MySequence requires 0 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*SvsNode](mNode.Node).MySequence()
			},
			"GetDataName": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 2 {
					err := fmt.Errorf("SvsNode.GetDataName requires 2 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				nodeId, ok := args[0].([]byte)
				if !ok && args[0] != nil {
					err := ndn.ErrInvalidValue{Item: "nodeId", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				seq, ok := args[1].(uint64)
				if !ok && args[1] != nil {
					err := ndn.ErrInvalidValue{Item: "seq", Value: args[1]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*SvsNode](mNode.Node).GetDataName(mNode, nodeId, seq)
			},
		},
		Create: CreateSvsNode,
	}
	schema.RegisterNodeImpl(SvsNodeDesc)
}
