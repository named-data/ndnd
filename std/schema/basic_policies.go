package schema

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/utils"
)

type RegisterPolicy struct {
	RegisterIf bool
	// It is map[string]any in json
	// but the any can be a string
	Patterns enc.Matching
}

// (AI GENERATED DESCRIPTION): Returns the `RegisterPolicy` instance itself as a `Policy` interface.
func (p *RegisterPolicy) PolicyTrait() Policy {
	return p
}

// (AI GENERATED DESCRIPTION): Registers the node’s name prefix with the engine when the RegisterPolicy is attached, panicking if the prefix cannot be initialized or the registration fails.
func (p *RegisterPolicy) onAttach(event *Event) any {
	node := event.TargetNode
	mNode := node.Apply(p.Patterns)
	if mNode == nil {
		panic("cannot initialize the name prefix to register")
	}
	err := node.Engine().RegisterRoute(mNode.Name)
	if err != nil {
		panic(fmt.Errorf("prefix registration failed: %+v", err))
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Adds the policy’s onAttach callback as an event listener on the node’s PropOnAttach event when RegisterIf is true.
func (p *RegisterPolicy) Apply(node *Node) {
	if p.RegisterIf {
		var callback Callback = p.onAttach
		node.AddEventListener(PropOnAttach, &callback)
	}
}

// (AI GENERATED DESCRIPTION): Creates a new RegisterPolicy configured to register by default (RegisterIf set to true).
func NewRegisterPolicy() Policy {
	return &RegisterPolicy{
		RegisterIf: true,
	}
}

type Sha256SignerPolicy struct{}

// (AI GENERATED DESCRIPTION): Returns the current `Sha256SignerPolicy` instance as a value of the `Policy` interface.
func (p *Sha256SignerPolicy) PolicyTrait() Policy {
	return p
}

// (AI GENERATED DESCRIPTION): Creates and returns a new `Sha256SignerPolicy` that implements the `Policy` interface.
func NewSha256SignerPolicy() Policy {
	return &Sha256SignerPolicy{}
}

// (AI GENERATED DESCRIPTION): Creates and returns a new SHA‑256 signer instance.
func (p *Sha256SignerPolicy) onGetDataSigner(*Event) any {
	return signer.NewSha256Signer()
}

// (AI GENERATED DESCRIPTION): Validates a Data packet’s SHA‑256 signature by recomputing the signature over its signed content and returning VrPass if it matches, VrFail if it does not, or VrSilence when the signature is absent or not of type SignatureDigestSha256.
func (p *Sha256SignerPolicy) onValidateData(event *Event) any {
	sigCovered := event.SigCovered
	signature := event.Signature
	if sigCovered == nil || signature == nil || signature.SigType() != ndn.SignatureDigestSha256 {
		return VrSilence
	}
	val, _ := signer.NewSha256Signer().Sign(sigCovered)
	if bytes.Equal(signature.SigValue(), val) {
		return VrPass
	} else {
		return VrFail
	}
}

// (AI GENERATED DESCRIPTION): Attaches the policy’s GetDataSigner and ValidateData handlers to the node’s events, registering the signer and enforcing a ValidateData event, and panics if the node does not support data validation.
func (p *Sha256SignerPolicy) Apply(node *Node) {
	// IdPtr must be used
	evt := node.GetEvent(PropOnGetDataSigner)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onGetDataSigner))
	}
	// PropOnValidateData must exist. Otherwise it is at an invalid path.
	evt = node.GetEvent(PropOnValidateData)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onValidateData))
	} else {
		panic("attaching Sha256SignerPolicy to a node that does not need to validate Data. What is the use?")
	}
}

type CacheEntry struct {
	RawData  enc.Wire
	Validity time.Time
}

// MemStoragePolicy is a policy that stored data in a memory storage.
// It will iteratively applies to all children in a subtree.
type MemStoragePolicy struct {
	timer ndn.Timer
	lock  sync.RWMutex
	// TODO: A better implementation would be MemStoragePolicy refers to an external storage
	// but not implement one itself.
	tree *basic_engine.NameTrie[CacheEntry]
}

// (AI GENERATED DESCRIPTION): Returns the MemStoragePolicy instance as a Policy interface.
func (p *MemStoragePolicy) PolicyTrait() Policy {
	return p
}

// (AI GENERATED DESCRIPTION): Retrieves the raw data for an entry whose name exactly matches the given name (or the first child node that meets the freshness check) from the in‑memory cache, returning nil if no such fresh entry exists.
func (p *MemStoragePolicy) Get(name enc.Name, canBePrefix bool, mustBeFresh bool) enc.Wire {
	p.lock.RLock()
	defer p.lock.RUnlock()

	node := p.tree.ExactMatch(name)
	now := time.Time{}
	if p.timer != nil {
		now = p.timer.Now()
	}
	if node == nil {
		return nil
	}
	freshTest := func(entry CacheEntry) bool {
		return len(entry.RawData) > 0 && (!mustBeFresh || entry.Validity.After(now))
	}
	if freshTest(node.Value()) {
		return node.Value().RawData
	}
	dataNode := node.FirstNodeIf(freshTest)
	if dataNode != nil {
		return dataNode.Value().RawData
	} else {
		return nil
	}
}

// (AI GENERATED DESCRIPTION): Stores raw data for the given name in the in‑memory cache, recording the data and its validity timestamp.
func (p *MemStoragePolicy) Put(name enc.Name, rawData enc.Wire, validity time.Time) {
	p.lock.Lock()
	defer p.lock.Unlock()

	node := p.tree.MatchAlways(name)
	node.SetValue(CacheEntry{
		RawData:  rawData,
		Validity: validity,
	})
}

// (AI GENERATED DESCRIPTION): Stores the target node’s engine timer in the policy’s timer field when the policy is attached, enabling future time‑based operations.
func (p *MemStoragePolicy) onAttach(event *Event) any {
	p.timer = event.TargetNode.Engine().Timer()
	return nil
}

// (AI GENERATED DESCRIPTION): Retrieves a stored Data packet matching the event’s target name, honoring the specified prefix‐matching and freshness flags.
func (p *MemStoragePolicy) onSearch(event *Event) any {
	// event.IntConfig is always valid for onSearch, no matter if there is an Interest.
	return p.Get(event.Target.Name, event.IntConfig.CanBePrefix, event.IntConfig.MustBeFresh)
}

// (AI GENERATED DESCRIPTION): Stores the event’s raw packet into the memory storage keyed by its target name, setting the packet’s validity to the current time plus the event’s specified valid duration.
func (p *MemStoragePolicy) onSave(event *Event) any {
	validity := p.timer.Now().Add(*event.ValidDuration)
	p.Put(event.Target.Name, event.RawPacket, validity)
	return nil
}

// (AI GENERATED DESCRIPTION): Registers the MemStoragePolicy callbacks (onAttach, onSearch, onSave) to the specified node and recursively to all of its child nodes.
func (p *MemStoragePolicy) Apply(node *Node) {
	// TODO: onAttach does not need to be called on every child...
	// But I don't have enough time to fix this
	if event := node.GetEvent(PropOnAttach); event != nil {
		event.Add(utils.IdPtr(p.onAttach))
	}
	if event := node.GetEvent(PropOnSearchStorage); event != nil {
		event.Add(utils.IdPtr(p.onSearch))
	}
	if event := node.GetEvent(PropOnSaveStorage); event != nil {
		event.Add(utils.IdPtr(p.onSave))
	}
	chd := node.Children()
	for _, c := range chd {
		p.Apply(c)
	}
}

// (AI GENERATED DESCRIPTION): Initializes a new MemStoragePolicy with an empty name trie for storing cache entries in memory.
func NewMemStoragePolicy() Policy {
	return &MemStoragePolicy{
		tree: basic_engine.NewNameTrie[CacheEntry](),
	}
}

type FixedHmacSignerPolicy struct {
	Key         string
	KeyName     enc.Name
	SignForCert bool
	ExpireTime  time.Duration
}

// (AI GENERATED DESCRIPTION): Returns the FixedHmacSignerPolicy itself as a Policy, allowing the instance to satisfy the Policy interface.
func (p *FixedHmacSignerPolicy) PolicyTrait() Policy {
	return p
}

// (AI GENERATED DESCRIPTION): Creates a FixedHmacSignerPolicy instance with certificate signing disabled (SignForCert set to false).
func NewFixedHmacSignerPolicy() Policy {
	return &FixedHmacSignerPolicy{
		SignForCert: false,
	}
}

// (AI GENERATED DESCRIPTION): Creates and returns a new HMAC signer initialized with the policy’s fixed key.
func (p *FixedHmacSignerPolicy) onGetDataSigner(*Event) any {
	return signer.NewHmacSigner([]byte(p.Key))
}

// (AI GENERATED DESCRIPTION): Validates a Data packet’s HMAC‑SHA256 signature using a fixed key, returning pass, fail, or silence if the signature is absent or not an HMAC type.
func (p *FixedHmacSignerPolicy) onValidateData(event *Event) any {
	sigCovered := event.SigCovered
	signature := event.Signature
	if sigCovered == nil || signature == nil || signature.SigType() != ndn.SignatureHmacWithSha256 {
		return VrSilence
	}
	if signer.ValidateHmac(sigCovered, signature, []byte(p.Key)) {
		return VrPass
	} else {
		return VrFail
	}
}

// (AI GENERATED DESCRIPTION): Applies a fixed‑HMAC signer policy to a node by registering the policy’s signer and validator callbacks, ensuring the node supports the necessary events and a key is supplied.
func (p *FixedHmacSignerPolicy) Apply(node *Node) {
	// key must present
	if len(p.Key) == 0 {
		panic("FixedHmacSignerPolicy requires key to present before apply.")
	}
	// IdPtr must be used
	evt := node.GetEvent(PropOnGetDataSigner)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onGetDataSigner))
	}
	// PropOnValidateData must exist. Otherwise it is at an invalid path.
	evt = node.GetEvent(PropOnValidateData)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onValidateData))
	} else {
		panic("applying FixedHmacSignerPolicy to a node that does not need to validate Data. What is the use?")
	}
}

type FixedHmacIntSignerPolicy struct {
	Key    string
	signer ndn.Signer
}

// (AI GENERATED DESCRIPTION): Returns the receiver’s own `FixedHmacIntSignerPolicy` instance as a `Policy` trait.
func (p *FixedHmacIntSignerPolicy) PolicyTrait() Policy {
	return p
}

// (AI GENERATED DESCRIPTION): Creates and returns a new `FixedHmacIntSignerPolicy` instance, implementing the Policy interface for HMAC-based signing.
func NewFixedHmacIntSignerPolicy() Policy {
	return &FixedHmacIntSignerPolicy{}
}

// (AI GENERATED DESCRIPTION): Returns the internal HMAC signer associated with the `FixedHmacIntSignerPolicy` when a “get signer” event is received.
func (p *FixedHmacIntSignerPolicy) onGetIntSigner(*Event) any {
	return p.signer
}

// (AI GENERATED DESCRIPTION): Validates an event’s HMAC‑SHA256 signature using the policy’s fixed key, returning pass if the signature matches, fail if it does not, or silence if the packet is not HMAC‑signed.
func (p *FixedHmacIntSignerPolicy) onValidateInt(event *Event) any {
	sigCovered := event.SigCovered
	signature := event.Signature
	if sigCovered == nil || signature == nil || signature.SigType() != ndn.SignatureHmacWithSha256 {
		return VrSilence
	}
	if signer.ValidateHmac(sigCovered, signature, []byte(p.Key)) {
		return VrPass
	} else {
		return VrFail
	}
}

// (AI GENERATED DESCRIPTION): Initializes the policy’s HMAC signer using the configured key when the policy is attached.
func (p *FixedHmacIntSignerPolicy) onAttach(event *Event) any {
	p.signer = signer.NewHmacSigner([]byte(p.Key))
	return nil
}

// (AI GENERATED DESCRIPTION): Applies a fixed‑HMAC signing policy to a node, registering callbacks for retrieving the Interest signer, validating incoming Interests, and handling node attachment while ensuring required events are present.
func (p *FixedHmacIntSignerPolicy) Apply(node *Node) {
	// key must present
	if len(p.Key) == 0 {
		panic("FixedHmacSignerPolicy requires key to present before apply.")
	}
	// IdPtr must be used
	evt := node.GetEvent(PropOnGetIntSigner)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onGetIntSigner))
	}
	// PropOnValidateInt must exist. Otherwise it is at an invalid path.
	evt = node.GetEvent(PropOnValidateInt)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onValidateInt))
	} else {
		panic("applying FixedHmacSignerPolicy to a node that does not need to validate Interest. What is the use?")
	}

	node.AddEventListener(PropOnAttach, utils.IdPtr(p.onAttach))
}

// (AI GENERATED DESCRIPTION): Registers available policy implementations by initializing their descriptors and adding them to the policy registry.
func initPolicies() {
	registerPolicyDesc := &PolicyImplDesc{
		ClassName: "RegisterPolicy",
		Properties: map[PropKey]PropertyDesc{
			"RegisterIf": DefaultPropertyDesc("RegisterIf"),
			"Patterns":   MatchingPropertyDesc("Patterns"),
		},
		Create: NewRegisterPolicy,
	}
	sha256SignerPolicyDesc := &PolicyImplDesc{
		ClassName: "Sha256Signer",
		Create:    NewSha256SignerPolicy,
	}
	RegisterPolicyImpl(registerPolicyDesc)
	RegisterPolicyImpl(sha256SignerPolicyDesc)
	memoryStoragePolicyDesc := &PolicyImplDesc{
		ClassName: "MemStorage",
		Create:    NewMemStoragePolicy,
	}
	RegisterPolicyImpl(memoryStoragePolicyDesc)

	fixedHmacSignerPolicyDesc := &PolicyImplDesc{
		ClassName: "FixedHmacSigner",
		Create:    NewFixedHmacSignerPolicy,
		Properties: map[PropKey]PropertyDesc{
			"KeyValue":    DefaultPropertyDesc("Key"),
			"KeyName":     NamePropertyDesc("KeyName"),
			"SignForCert": DefaultPropertyDesc("SignForCert"),
			"ExpireTime":  TimePropertyDesc("ExpireTime"),
		},
	}
	RegisterPolicyImpl(fixedHmacSignerPolicyDesc)

	fixedHmacIntSignerPolicyDesc := &PolicyImplDesc{
		ClassName: "FixedHmacIntSigner",
		Create:    NewFixedHmacIntSignerPolicy,
		Properties: map[PropKey]PropertyDesc{
			"KeyValue": DefaultPropertyDesc("Key"),
		},
	}
	RegisterPolicyImpl(fixedHmacIntSignerPolicyDesc)
}
