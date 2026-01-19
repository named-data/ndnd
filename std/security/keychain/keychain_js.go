//go:build js && wasm

package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"syscall/js"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
	sig "github.com/named-data/ndnd/std/security/signer"
	jsutil "github.com/named-data/ndnd/std/utils/js"
)

// KeyChainJS is a JS-based keychain.
type KeyChainJS struct {
	state *keyChainState
	api   js.Value
}

// NewKeyChainJS creates a new JS-based keychain.
// See keychain_js.ts for the interface and a sample implementation.
func NewKeyChainJS(api js.Value, pubStore ndn.Store) (ndn.KeyChain, error) {
	kc := &KeyChainJS{
		state: newKeyChainState(pubStore),
		api:   api,
	}

	list, err := jsutil.Await(api.Call("list"))
	if err != nil {
		return nil, err
	}

	callback := js.FuncOf(func(this js.Value, args []js.Value) any {
		err := InsertFile(kc, jsutil.JsArrayToSlice(args[0]))
		if err != nil {
			log.Error(kc, "Failed to insert keychain entry", "err", err)
		}

		return nil
	})
	list.Call("forEach", callback)
	callback.Release()

	return kc, nil
}

// (AI GENERATED DESCRIPTION): Returns the string representation of the KeyChainJS instance, which is the literal `"keychain-js"`.
func (kc *KeyChainJS) String() string {
	return "keychain-js"
}

// (AI GENERATED DESCRIPTION): Returns the in-memory store backing the KeyChainJS instance.
func (kc *KeyChainJS) Store() ndn.Store {
	return kc.state.pubStore
}

// (AI GENERATED DESCRIPTION): Retrieves and returns a slice of all key‑chain identities stored in the KeyChainJS memory store.
func (kc *KeyChainJS) Identities() []ndn.KeyChainIdentity {
	return kc.state.Identities()
}

// (AI GENERATED DESCRIPTION): Returns the KeyChainIdentity with the specified name from the KeyChainJS in‑memory store.
func (kc *KeyChainJS) IdentityByName(name enc.Name) ndn.KeyChainIdentity {
	return kc.state.IdentityByName(name)
}

// (AI GENERATED DESCRIPTION): Inserts a signer into the in‑memory keychain and persists its secret to a file.
func (kc *KeyChainJS) InsertKey(signer ndn.Signer) error {
	err := kc.state.insertKey(signer)
	if err != nil {
		return err
	}

	secret, err := sig.MarshalSecret(signer)
	if err != nil {
		return err
	}

	return kc.writeFile(secret.Join(), EXT_KEY)
}

// (AI GENERATED DESCRIPTION): Inserts the given certificate into the keychain’s in‑memory store and writes it to a file.
func (kc *KeyChainJS) InsertCert(wire []byte) error {
	err := kc.state.insertCert(wire)
	if err != nil {
		return err
	}

	return kc.writeFile(wire, EXT_CERT)
}

// DeleteKey removes a key and its certificates from the in-memory keychain and browser storage.
func (kc *KeyChainJS) DeleteKey(keyName enc.Name) error {
	idName, err := sec.GetIdentityFromKeyName(keyName)
	if err != nil {
		return err
	}

	id := kc.state.IdentityByName(idName)
	if id == nil {
		return enc.ErrNotFound{Key: keyName.String()}
	}

	var signer ndn.Signer
	for _, key := range id.Keys() {
		if key.KeyName().Equal(keyName) {
			signer = key.Signer()
			break
		}
	}
	if signer == nil {
		return enc.ErrNotFound{Key: keyName.String()}
	}

	secret, err := sig.MarshalSecret(signer)
	if err != nil {
		return err
	}

	certWires := make([][]byte, 0)
	for _, cert := range kc.state.CertNames() {
		if keyName.IsPrefix(cert) {
			wire, err := kc.Store().Get(cert, false)
			if err != nil {
				return err
			}
			if wire != nil {
				certWires = append(certWires, wire)
			}
		}
	}

	if err := kc.state.deleteKey(keyName); err != nil {
		return err
	}

	if err := kc.deleteFile(secret.Join(), EXT_KEY); err != nil {
		return err
	}
	for _, wire := range certWires {
		if err := kc.deleteFile(wire, EXT_CERT); err != nil {
			return err
		}
	}
	return nil
}

// DeleteCert removes a certificate from the in-memory keychain and browser storage.
func (kc *KeyChainJS) DeleteCert(name enc.Name) error {
	wire, err := kc.Store().Get(name, false)
	if err != nil {
		return err
	}
	if wire == nil {
		return enc.ErrNotFound{Key: name.String()}
	}

	if err := kc.state.deleteCert(name); err != nil {
		return err
	}

	return kc.deleteFile(wire, EXT_CERT)
}

// (AI GENERATED DESCRIPTION): Writes a binary blob to local storage under a name derived from its SHA‑256 hash, appending the specified extension, via the JavaScript API.
func (kc *KeyChainJS) writeFile(wire []byte, ext string) error {
	hash := sha256.Sum256(wire)
	filename := hex.EncodeToString(hash[:])

	kc.api.Call("write", filename+ext, jsutil.SliceToJsArray(wire))
	return nil
}

func (kc *KeyChainJS) deleteFile(wire []byte, ext string) error {
	hash := sha256.Sum256(wire)
	filename := hex.EncodeToString(hash[:])

	kc.api.Call("delete", filename+ext)
	return nil
}
