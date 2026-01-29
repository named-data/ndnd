package schema

import (
	"errors"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

type NeedResult struct {
	// Status is the result of Need (data, NACKed, timed out, validation failure)
	Status ndn.InterestResult
	// Content is the needed data object
	Content enc.Wire
	// Data packet if available. Note that this may be nil if the node aggregates multiple packets.
	// Please use Extra to obtain extra info in that case.
	Data ndn.Data
	// ValidResult is the result of validation of this data object
	ValidResult *ValidRes
	// NackReason is the reason for NACK
	NackReason *uint64
	// Extra info used by application
	Extra map[string]any
}

// (AI GENERATED DESCRIPTION): Returns the InterestResult status and the content wire contained in a NeedResult.
func (r NeedResult) Get() (ndn.InterestResult, enc.Wire) {
	return r.Status, r.Content
}

type ExpressPoint struct {
	BaseNodeImpl

	OnInt           *EventTarget
	OnValidateInt   *EventTarget
	OnValidateData  *EventTarget
	OnSearchStorage *EventTarget
	OnSaveStorage   *EventTarget
	OnGetIntSigner  *EventTarget

	CanBePrefix bool
	MustBeFresh bool
	Lifetime    time.Duration
	SupressInt  bool
}

// (AI GENERATED DESCRIPTION): Returns the constant string `"express-point"` as the string representation of an `ExpressPoint`.
func (n *ExpressPoint) String() string {
	return "express-point"
}

// (AI GENERATED DESCRIPTION): Returns the ExpressPoint instance itself as a `NodeImpl`, enabling it to be used wherever a `NodeImpl` is required.
func (n *ExpressPoint) NodeImplTrait() NodeImpl {
	return n
}

// (AI GENERATED DESCRIPTION): Searches the ExpressPoint’s storage for a Data packet that satisfies the Interest’s CanBePrefix and MustBeFresh configuration and returns the cached Data if one is found.
func (n *ExpressPoint) SearchCache(event *Event) enc.Wire {
	// SearchCache can be triggered by both incoming Interest and outgoing Interest.
	// To make the input unified, we set mustBeFresh and CanBePrefix here.
	setIntCfg := event.IntConfig == nil
	if setIntCfg {
		event.IntConfig = &ndn.InterestConfig{
			CanBePrefix: event.Interest.CanBePrefix(),
			MustBeFresh: event.Interest.MustBeFresh(),
		}
	}
	ret := n.OnSearchStorage.DispatchUntil(event, func(a any) bool {
		wire, ok := a.(enc.Wire)
		return ok && len(wire) > 0
	})
	cachedData, ok := ret.(enc.Wire)
	if setIntCfg {
		event.IntConfig = nil
	}
	if ok {
		return cachedData
	} else {
		return nil
	}
}

// (AI GENERATED DESCRIPTION): Handles an incoming Interest by first checking the cache for a matching Data packet, validating the Interest’s signature (if any), and then dispatching the request to registered handlers to generate and reply with the appropriate Data.
func (n *ExpressPoint) OnInterest(args ndn.InterestHandlerArgs, matching enc.Matching) {
	node := n.Node
	event := &Event{
		TargetNode: node,
		Target: &MatchedNode{
			Node:     node,
			Matching: matching,
			Name:     args.Interest.Name(),
		},
		RawPacket:  args.RawInterest,
		SigCovered: args.SigCovered,
		Interest:   args.Interest,
		Signature:  args.Interest.Signature(),
		Reply:      args.Reply,
		Deadline:   &args.Deadline,
		Content:    args.Interest.AppParam(),
	}

	// Handle FullName: the implicit sha256 component should be removed from data name
	if event.Target.Name[len(event.Target.Name)-1].Typ == enc.TypeImplicitSha256DigestComponent {
		event.Target.Name = event.Target.Name[:len(event.Target.Name)-1]
	}
	// The info is stored in Target.Matching
	// Even without this info, the data packet is supposed to be unique.

	// Search storage
	// Reply if there is data (including AppNack). No further callback will be called if hit.
	// This is the same behavior as a forwarder.
	cachedData := n.SearchCache(event)
	if len(cachedData) > 0 {
		err := args.Reply(cachedData)
		if err != nil {
			log.Error(n, "Unable to reply Interest - DROP", "err", err)
		}
		return
	}

	go func() {
		// Validate Interest
		// Only done when there is a signature.
		// TODO: Validate Sha256 in name
		if args.Interest.Signature().SigType() != ndn.SignatureNone || args.Interest.AppParam() != nil {
			validRes := VrSilence
			event.ValidResult = &validRes
			ret := n.OnValidateInt.DispatchUntil(event, func(a any) bool {
				res, ok := a.(ValidRes)
				event.ValidResult = &res
				return !ok || res < VrSilence || res >= VrBypass
			})
			res, ok := ret.(ValidRes)
			if !ok || res < VrSilence {
				log.Warn(n, "Verification failed for Interest - DROP", "res", res)
				return
			}
			if res == VrSilence {
				log.Warn(n, "Unverified Interest - DROP")
				return
			}
		}

		// PreRecvInt
		// Used to decrypt AppParam or handle before onInterest hits, if applicable.
		// Do we need them? Hold for now.

		// OnInt
		n.OnInt.DispatchUntil(event, func(a any) bool {
			isDone, ok := a.(bool)
			return ok && isDone
		})

		// PreSendData
		// Used to encrypt Data or handle after onInterest hits, if applicable.
		// Do we need them? Hold for now.
	}()
}

// NeedCallback is callback version of Need().
// The Need() function to obtain the corresponding Data. May express an Interest if the Data is not stored.
// `intConfig` is optional and if given, will overwrite the default setting.
// The callback function will be called in another goroutine no matter what the result is.
// So if `callback` can handle errors, it is safe to ignore the return value.
// TODO: (Urgent) NeedXXX needs a way for the user to optionally specify the deadline of the Interest
// without touching anything else in intConfig
func (n *ExpressPoint) NeedCallback(
	mNode MatchedNode, callback Callback, appParam enc.Wire, intConfig *ndn.InterestConfig, suppress bool,
) error {
	if mNode.Node != n.Node {
		panic("NTSchema tree compromised.")
	}
	// ret := make(chan NeedResult, 1)
	node := n.Node
	engine := n.Node.engine
	spec := engine.Spec()
	if intConfig == nil {
		intConfig = &ndn.InterestConfig{
			CanBePrefix:    n.CanBePrefix,
			MustBeFresh:    n.MustBeFresh,
			Lifetime:       optional.Some(n.Lifetime),
			Nonce:          utils.ConvertNonce(engine.Timer().Nonce()),
			HopLimit:       nil,
			ForwardingHint: nil,
		}
	}
	event := &Event{
		TargetNode: node,
		Target:     &mNode,
		IntConfig:  intConfig,
		Content:    appParam,
	}

	// If appParam is empty and not signed, the Interest name is final.
	// Otherwise, we have to construct the Interest first before searching storage.
	// Get a signer for Interest.
	evtRet := n.OnGetIntSigner.DispatchUntil(event, func(a any) bool {
		ret, ok := a.(ndn.Signer)
		return ok && ret != nil
	})
	signer, ok := evtRet.(ndn.Signer)
	if (!ok || signer == nil) && appParam == nil {
		cachedData := n.SearchCache(event)
		if cachedData != nil {
			data, sigCovered, err := spec.ReadData(enc.NewWireView(cachedData))
			if err == nil {
				dataMatch := mNode.Refine(data.Name())
				cbEvt := &Event{
					TargetNode:   node,
					Target:       dataMatch,
					RawPacket:    cachedData,
					SigCovered:   sigCovered,
					Signature:    data.Signature(),
					Data:         data,
					Content:      data.Content(),
					ValidResult:  utils.IdPtr(VrCachedData),
					NeedStatus:   utils.IdPtr(ndn.InterestResultData),
					SelfProduced: utils.IdPtr(true),
				}
				go callback(cbEvt)
				// ret <- NeedResult{ndn.InterestResultData, data.Content(), data, cachedData, VrCachedData}
				// close(ret)
				// return ret
				return nil
			} else {
				log.Error(n, "The storage returned an invalid data")
			}
		}
		// storageSearched = true
	}

	// Construct Interest
	interest, err := spec.MakeInterest(mNode.Name, intConfig, appParam, signer)
	if err != nil {
		log.Error(n, "Unable to encode Interest in Need()", "err", err)
		go callback(&Event{
			TargetNode: node,
			NeedStatus: utils.IdPtr(ndn.InterestResultNone),
		})
		return errors.New("unable to construct Interest")
	}

	// We may search the storage if not yet
	// if !storageSearched {
	// 	// Since it is not useful generally, skip for now.
	// }
	if n.SupressInt || suppress {
		go callback(&Event{
			TargetNode: node,
			NeedStatus: utils.IdPtr(ndn.InterestResultNack),
		})
		return nil
	}

	// Set the deadline
	// assert(intCfg.Lifetime != nil)
	var deadline *time.Time
	if intConfig.Lifetime.IsSet() {
		deadline = utils.IdPtr(engine.Timer().Now().Add(intConfig.Lifetime.Unwrap()))
	} else {
		deadline = nil
	}
	cbEvt := &Event{
		TargetNode:   node,
		Target:       &mNode,
		Deadline:     deadline,
		SelfProduced: utils.IdPtr(false),
	}

	// Express the Interest
	// Note that this function runs on a different go routine than the callback.
	// To avoid clogging the engine, the callback needs to return ASAP, so an inner goroutine is created.
	err = engine.Express(interest, func(args ndn.ExpressCallbackArgs) {
		if args.Result != ndn.InterestResultData {
			if args.Result == ndn.InterestResultNack {
				cbEvt.NackReason = &args.NackReason
			}
			cbEvt.NeedStatus = utils.IdPtr(args.Result)
			go callback(cbEvt)
			return
		}

		go func() {
			data := args.Data
			dataMatch := mNode.Refine(data.Name())
			cbEvt.Target = dataMatch
			cbEvt.Data = data
			cbEvt.RawPacket = args.RawData
			cbEvt.SelfProduced = utils.IdPtr(false)
			cbEvt.SigCovered = args.SigCovered
			cbEvt.Content = data.Content()
			cbEvt.Signature = data.Signature()

			// Validate data
			validRes := VrSilence
			cbEvt.ValidResult = &validRes
			ret := n.OnValidateData.DispatchUntil(cbEvt, func(a any) bool {
				res, ok := a.(ValidRes)
				cbEvt.ValidResult = &res
				return !ok || res < VrSilence || res >= VrBypass
			})
			res, ok := ret.(ValidRes)
			if ok {
				cbEvt.ValidResult = &res
			}
			if !ok || res < VrSilence {
				log.Warn(n, "Verification failed for Data - DROP", "res", res)
				cbEvt.NeedStatus = utils.IdPtr(ndn.InterestResultUnverified)
				cbEvt.Content = nil
				callback(cbEvt)
				return
			}
			if res == VrSilence {
				log.Warn(n, "Unverified Data - DROP", "res", res)
				cbEvt.NeedStatus = utils.IdPtr(ndn.InterestResultUnverified)
				cbEvt.Content = nil
				callback(cbEvt)
				return
			}
			cbEvt.NeedStatus = utils.IdPtr(ndn.InterestResultData)

			// Save (cache) the data in the storage
			cbEvt.ValidDuration = nil
			if freshness, ok := data.Freshness().Get(); ok {
				cbEvt.ValidDuration = utils.IdPtr(freshness)
			}
			n.OnSaveStorage.Dispatch(cbEvt)

			// Return the result
			callback(cbEvt)
		}()
	})
	if err != nil {
		log.Warn(n, "Failed to express Interest")
		go callback(&Event{
			TargetNode: node,
			NeedStatus: utils.IdPtr(ndn.InterestResultNone),
		})
	}
	return err
}

// NeedChan is the channel version of Need()
func (n *ExpressPoint) NeedChan(
	mNode MatchedNode, appParam enc.Wire, intConfig *ndn.InterestConfig, suppress bool,
) chan NeedResult {
	ret := make(chan NeedResult, 1)
	callback := func(event *Event) any {
		result := NeedResult{
			Status:      *event.NeedStatus,
			Content:     event.Content,
			Data:        event.Data,
			ValidResult: event.ValidResult,
			NackReason:  event.NackReason,
		}
		ret <- result
		close(ret)
		return nil
	}
	n.NeedCallback(mNode, callback, appParam, intConfig, suppress)
	return ret
}

// (AI GENERATED DESCRIPTION): Creates a new ExpressPoint node implementation, initializing it with default event targets and configuration flags for prefix handling, freshness, and storage behavior.
func CreateExpressPoint(node *Node) NodeImpl {
	return &ExpressPoint{
		BaseNodeImpl: BaseNodeImpl{
			Node:        node,
			OnAttachEvt: &EventTarget{},
			OnDetachEvt: &EventTarget{},
		},
		CanBePrefix:     true,
		MustBeFresh:     true,
		Lifetime:        4 * time.Second,
		SupressInt:      false,
		OnInt:           &EventTarget{},
		OnValidateInt:   &EventTarget{},
		OnValidateData:  &EventTarget{},
		OnSearchStorage: &EventTarget{},
		OnSaveStorage:   &EventTarget{},
		OnGetIntSigner:  &EventTarget{},
	}
}

var ExpressPointDesc *NodeImplDesc

// (AI GENERATED DESCRIPTION): Initializes and registers the ExpressPoint node descriptor, defining its properties, events and API functions (Need and NeedChan) in the node implementation registry.
func initExpressPointDesc() {
	ExpressPointDesc = &NodeImplDesc{
		ClassName: "ExpressPoint",
		Properties: map[PropKey]PropertyDesc{
			PropCanBePrefix: DefaultPropertyDesc(PropCanBePrefix),
			PropMustBeFresh: DefaultPropertyDesc(PropMustBeFresh),
			PropLifetime:    TimePropertyDesc(PropLifetime),
			PropSuppressInt: DefaultPropertyDesc(PropSuppressInt),
		},
		Events: map[PropKey]EventGetter{
			PropOnAttach:        DefaultEventTarget(PropOnAttach),   // Inherited from base
			PropOnDetach:        DefaultEventTarget(PropOnDetach),   // Inherited from base
			"OnInterest":        DefaultEventTarget(PropOnInterest), // This has a name conflict problem
			PropOnValidateInt:   DefaultEventTarget(PropOnValidateInt),
			PropOnValidateData:  DefaultEventTarget(PropOnValidateData),
			PropOnSearchStorage: DefaultEventTarget(PropOnSearchStorage),
			PropOnSaveStorage:   DefaultEventTarget(PropOnSaveStorage),
			PropOnGetIntSigner:  DefaultEventTarget(PropOnGetIntSigner),
		},
		Functions: map[string]NodeFunc{
			"Need": func(mNode MatchedNode, args ...any) any {
				if len(args) < 1 || len(args) > 4 {
					err := fmt.Errorf("ExpressPoint.Need requires 1~4 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				callback, ok := args[0].(Callback)
				if !ok {
					err := ndn.ErrInvalidValue{Item: "callback", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				var appParam enc.Wire = nil
				if len(args) >= 2 {
					appParam, ok = args[1].(enc.Wire)
					if !ok && args[1] != nil {
						err := ndn.ErrInvalidValue{Item: "appParam", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				var intConfig (*ndn.InterestConfig)
				if len(args) >= 3 {
					intConfig, ok = args[2].(*ndn.InterestConfig)
					if !ok && args[2] != nil {
						err := ndn.ErrInvalidValue{Item: "intConfig", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				var suppress bool = false
				if len(args) >= 4 {
					suppress, ok = args[3].(bool)
					if !ok {
						err := ndn.ErrInvalidValue{Item: "suppress", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				return QueryInterface[*ExpressPoint](mNode.Node).NeedCallback(mNode, callback, appParam, intConfig, suppress)
			},
			"NeedChan": func(mNode MatchedNode, args ...any) any {
				if len(args) > 3 {
					err := fmt.Errorf("ExpressPoint.NeedChan requires 0~3 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				var appParam enc.Wire = nil
				var ok bool = true
				if len(args) >= 1 {
					appParam, ok = args[0].(enc.Wire)
					if !ok && args[0] != nil {
						err := ndn.ErrInvalidValue{Item: "appParam", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				var intConfig (*ndn.InterestConfig)
				if len(args) >= 2 {
					intConfig, ok = args[1].(*ndn.InterestConfig)
					if !ok && args[1] != nil {
						err := ndn.ErrInvalidValue{Item: "intConfig", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				var suppress bool = false
				if len(args) >= 3 {
					suppress, ok = args[2].(bool)
					if !ok {
						err := ndn.ErrInvalidValue{Item: "suppress", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				return QueryInterface[*ExpressPoint](mNode.Node).NeedChan(mNode, appParam, intConfig, suppress)
			},
		},
		Create: CreateExpressPoint,
	}
	RegisterNodeImpl(ExpressPointDesc)
}

// (AI GENERATED DESCRIPTION): Returns the ExpressPoint as the requested type (ExpressPoint or BaseNodeImpl) or nil if the requested type is unsupported.
func (n *ExpressPoint) CastTo(ptr any) any {
	switch ptr.(type) {
	case (*ExpressPoint):
		return n
	case (*BaseNodeImpl):
		return &(n.BaseNodeImpl)
	default:
		return nil
	}
}
