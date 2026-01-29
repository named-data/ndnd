package keychain

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// KeyChainMem is an in-memory keychain.
type KeyChainMem struct {
	state *keyChainState
}

// NewKeyChainMem creates a new in-memory keychain.
func NewKeyChainMem(pubStore ndn.Store) *KeyChainMem {
	return &KeyChainMem{
		state: newKeyChainState(pubStore),
	}
}

// (AI GENERATED DESCRIPTION): Returns the string identifier `"keychain-mem"` for the in‑memory keychain instance.
func (kc *KeyChainMem) String() string {
	return "keychain-mem"
}

// (AI GENERATED DESCRIPTION): Returns the in‑memory public‑key store associated with the KeyChainMem instance.
func (kc *KeyChainMem) Store() ndn.Store {
	return kc.state.pubStore
}

// (AI GENERATED DESCRIPTION): Returns a slice of all identities currently stored in the in‑memory key chain.
func (kc *KeyChainMem) Identities() []ndn.KeyChainIdentity {
	return kc.state.Identities()
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the KeyChainIdentity from the in‑memory keychain that has the specified name, or nil if no matching identity exists.
func (kc *KeyChainMem) IdentityByName(name enc.Name) ndn.KeyChainIdentity {
	return kc.state.IdentityByName(name)
}

// (AI GENERATED DESCRIPTION): Adds a signer key to the in‑memory key chain, creating its identity if needed and linking any existing certificates whose names are prefixed by the key name.
func (kc *KeyChainMem) InsertKey(signer ndn.Signer) error {
	return kc.state.insertKey(signer)
}

// (AI GENERATED DESCRIPTION): Adds a certificate to the in‑memory key chain after validating its type, format, and expiration, ensuring it is not a duplicate, storing it in the public store, and updating all identities that reference it.
func (kc *KeyChainMem) InsertCert(wire []byte) error {
	return kc.state.insertCert(wire)
}

// DeleteKey removes a key and its certificates from the keychain.
func (kc *KeyChainMem) DeleteKey(keyName enc.Name) error {
	return kc.state.deleteKey(keyName)
}

// DeleteCert removes a certificate from the keychain.
func (kc *KeyChainMem) DeleteCert(name enc.Name) error {
	return kc.state.deleteCert(name)
}
