package demosec

import (
	"fmt"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/utils"
)

// KeyStoragePolicy is a policy that stored HMAC keys in a memory storage.
type KeyStoragePolicy struct {
	lock     sync.RWMutex
	KeyStore *DemoHmacKeyStore
}

// (AI GENERATED DESCRIPTION): Returns the string `"KeyStoragePolicy"` as the textual representation of this policy type.
func (p *KeyStoragePolicy) String() string {
	return "KeyStoragePolicy"
}

// (AI GENERATED DESCRIPTION): Returns the KeyStoragePolicy instance as a `schema.Policy`, enabling it to satisfy the `PolicyTrait` interface.
func (p *KeyStoragePolicy) PolicyTrait() schema.Policy {
	return p
}

// (AI GENERATED DESCRIPTION): Handles a search event by looking up the requested name in the key store, returning its certificate data as a Wire, and rejecting any prefix‐matching interests.
func (p *KeyStoragePolicy) onSearch(event *schema.Event) any {
	p.lock.RLock()
	defer p.lock.RUnlock()

	// event.IntConfig is always valid for onSearch, no matter if there is an Interest.
	if event.IntConfig.CanBePrefix {
		log.Error(p, "the Demo HMAC key storage does not support CanBePrefix Interest to fetch certificates.")
		return nil
	}
	key := p.KeyStore.GetKey(event.Target.Name)
	if key == nil {
		return nil
	}
	return enc.Wire{key.CertData}
}

// (AI GENERATED DESCRIPTION): Stores the key from the provided event into the policy’s KeyStore, marking it as fresh forever.
func (p *KeyStoragePolicy) onSave(event *schema.Event) any {
	p.lock.Lock()
	defer p.lock.Unlock()

	// NOTE: here we consider keys are fresh forever for simplicity
	p.KeyStore.SaveKey(event.Target.Name, event.Content.Join(), event.RawPacket.Join())
	return nil
}

// (AI GENERATED DESCRIPTION): Ensures the policy’s KeyStore is configured, panicking if it is nil, and otherwise does nothing (returns nil).
func (p *KeyStoragePolicy) onAttach(event *schema.Event) any {
	if p.KeyStore == nil {
		panic("you must set KeyStore property to be a DemoHmacKeyStore instance in Go.")
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Recursively attaches the policy’s onAttach, onSearch, and onSave event handlers to a schema node and all its descendant nodes.
func (p *KeyStoragePolicy) Apply(node *schema.Node) {
	// TODO: onAttach does not need to be called on every child...
	// But I don't have enough time to fix this
	if event := node.GetEvent(schema.PropOnAttach); event != nil {
		event.Add(utils.IdPtr(p.onAttach))
	}
	if event := node.GetEvent(schema.PropOnSearchStorage); event != nil {
		event.Add(utils.IdPtr(p.onSearch))
	}
	if event := node.GetEvent(schema.PropOnSaveStorage); event != nil {
		event.Add(utils.IdPtr(p.onSave))
	}
	chd := node.Children()
	for _, c := range chd {
		p.Apply(c)
	}
}

// (AI GENERATED DESCRIPTION): Creates a new KeyStoragePolicy instance and returns it as a schema.Policy.
func NewKeyStoragePolicy() schema.Policy {
	return &KeyStoragePolicy{}
}

// SignedByPolicy is a demo policy that specifies the trust schema.
type SignedByPolicy struct {
	Mapping     map[string]any
	KeyStore    *DemoHmacKeyStore
	KeyNodePath string

	keyNode *schema.Node
}

// (AI GENERATED DESCRIPTION): Returns the string literal `"SignedByPolicy"` as the human‑readable name of the policy.
func (p *SignedByPolicy) String() string {
	return "SignedByPolicy"
}

// (AI GENERATED DESCRIPTION): Returns the `SignedByPolicy` instance as a `schema.Policy`, enabling it to satisfy the Policy interface.
func (p *SignedByPolicy) PolicyTrait() schema.Policy {
	return p
}

// ConvertName converts a Data name to the name of the key to sign it.
// In real-world scenario, there should be two functions:
// - one suggests the key for the data produced by the current node
// - one checks if the signing key for a fetched data is correct
// In this simple demo I merge them into one for simplicity
func (p *SignedByPolicy) ConvertName(mNode *schema.MatchedNode) *schema.MatchedNode {
	newMatching := make(enc.Matching, len(mNode.Matching))
	for k, v := range mNode.Matching {
		if newV, ok := p.Mapping[k]; ok {
			// Be careful of crash
			newMatching[k] = []byte(newV.(string))
		} else {
			newMatching[k] = v
		}
	}
	return p.keyNode.Apply(newMatching)
}

// (AI GENERATED DESCRIPTION): Creates an HMAC signer for the event’s target name, returning nil and logging an error if the key name cannot be constructed or the key is missing.
func (p *SignedByPolicy) onGetDataSigner(event *schema.Event) any {
	keyMNode := p.ConvertName(event.Target)
	if keyMNode == nil {
		log.Error(p, "Cannot construct the key name to sign this data. Leave unsigned.")
		return nil
	}
	key := p.KeyStore.GetKey(keyMNode.Name)
	if key == nil {
		log.Error(p, "The key to sign this data is missing. Leave unsigned.")
		return nil
	}
	return signer.NewHmacSigner(key.KeyBits)
}

// (AI GENERATED DESCRIPTION): Validates a Data packet’s HMAC‑SHA256 signature by retrieving the signing key for the packet’s target name and verifying the signature, returning Pass, Fail, or Silence accordingly.
func (p *SignedByPolicy) onValidateData(event *schema.Event) any {
	sigCovered := event.SigCovered
	signature := event.Signature
	if sigCovered == nil || signature == nil || signature.SigType() != ndn.SignatureHmacWithSha256 {
		return schema.VrSilence
	}
	keyMNode := p.ConvertName(event.Target)
	//TODO: Compute the deadline
	result := <-keyMNode.Call("NeedChan").(chan schema.NeedResult)
	if result.Status != ndn.InterestResultData {
		log.Warn(p, "Unable to fetch the key that signed this data.")
		return schema.VrFail
	}
	if signer.ValidateHmac(sigCovered, signature, result.Content.Join()) {
		return schema.VrPass
	} else {
		log.Warn(p, "Failed to verify the signature.")
		return schema.VrFail
	}
}

// (AI GENERATED DESCRIPTION): When attached, the function ensures a KeyStore is configured, resolves the specified KeyNodePath to a node in the event’s target tree, stores that node for later use, and panics if any step fails.
func (p *SignedByPolicy) onAttach(event *schema.Event) any {
	if p.KeyStore == nil {
		panic("you must set KeyStore property to be a DemoHmacKeyStore instance in Go.")
	}

	pathPat, err := enc.NamePatternFromStr(p.KeyNodePath)
	if err != nil {
		panic(fmt.Errorf("KeyNodePath is invalid: %+v", p.KeyNodePath))
	}
	p.keyNode = event.TargetNode.RootNode().At(pathPat)
	if p.keyNode == nil {
		panic(fmt.Errorf("specified KeyNodePath does not correspond to a valid node: %+v", p.KeyNodePath))
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Attaches a SignedByPolicy to a node by registering its onAttach, onGetDataSigner, and onValidateData callbacks to the node’s corresponding events, panicking if the node does not provide a data‑validation event.
func (p *SignedByPolicy) Apply(node *schema.Node) {
	if event := node.GetEvent(schema.PropOnAttach); event != nil {
		event.Add(utils.IdPtr(p.onAttach))
	}
	evt := node.GetEvent(schema.PropOnGetDataSigner)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onGetDataSigner))
	}
	// PropOnValidateData must exist. Otherwise it is at an invalid path.
	evt = node.GetEvent(schema.PropOnValidateData)
	if evt != nil {
		evt.Add(utils.IdPtr(p.onValidateData))
	} else {
		panic("attaching SignedByPolicy to a node that does not need to validate Data. What is the use?")
	}
}

// (AI GENERATED DESCRIPTION): Creates a new SignedByPolicy policy instance (with default/empty configuration).
func NewSignedByPolicy() schema.Policy {
	return &SignedByPolicy{}
}

// (AI GENERATED DESCRIPTION): Registers the KeyStoragePolicy and SignedBy policy implementations with the schema registry.
func init() {
	keyStoragePolicyDesc := &schema.PolicyImplDesc{
		ClassName: "KeyStoragePolicy",
		Create:    NewKeyStoragePolicy,
		Properties: map[schema.PropKey]schema.PropertyDesc{
			"KeyStore": schema.DefaultPropertyDesc("KeyStore"),
		},
	}
	schema.RegisterPolicyImpl(keyStoragePolicyDesc)

	signedByPolicyDesc := &schema.PolicyImplDesc{
		ClassName: "SignedBy",
		Create:    NewSignedByPolicy,
		Properties: map[schema.PropKey]schema.PropertyDesc{
			"Mapping":     schema.DefaultPropertyDesc("Mapping"),
			"KeyStore":    schema.DefaultPropertyDesc("KeyStore"),
			"KeyNodePath": schema.DefaultPropertyDesc("KeyNodePath"),
		},
	}
	schema.RegisterPolicyImpl(signedByPolicyDesc)
}
