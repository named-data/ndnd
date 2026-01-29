package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
	sig "github.com/named-data/ndnd/std/security/signer"
)

const EXT_KEY = ".key"
const EXT_CERT = ".cert"
const EXT_PEM = ".pem"

// KeyChainDir is a directory-based keychain.
type KeyChainDir struct {
	state *keyChainState
	path  string
	files map[string]string
	refs  map[string]int
}

// NewKeyChainDir creates a new in-memory keychain.
func NewKeyChainDir(path string, pubStore ndn.Store) (ndn.KeyChain, error) {
	kc := &KeyChainDir{
		state: newKeyChainState(pubStore),
		path:  path,
		files: make(map[string]string),
		refs:  make(map[string]int),
	}

	// Create directory if it doesn't exist
	err := os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}

	// Populate keychain from disk
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), EXT_KEY) &&
			!strings.HasSuffix(entry.Name(), EXT_CERT) &&
			!strings.HasSuffix(entry.Name(), EXT_PEM) {
			continue
		}

		if entry.IsDir() {
			continue
		}

		filename := filepath.Join(path, entry.Name())
		written := make(map[string]struct{})
		content, err := os.ReadFile(filename)
		if err != nil {
			log.Warn(kc, "Failed to read keychain entry", "file", filename, "err", err)
			continue
		}

		signers, certs, err := sec.DecodeFile(content)
		if err != nil {
			log.Error(kc, "Failed to parse keychain entry", "file", filename, "err", err)
			continue
		}

		// Normalize keys and certs for hashed names
		for _, wire := range certs {
			if err := kc.state.insertCert(wire); err != nil {
				log.Error(kc, "Failed to insert keychain certificate", "file", filename, "err", err)
				continue
			}
			path, err := kc.writeFile(wire, EXT_CERT)
			if err != nil {
				log.Error(kc, "Failed to persist keychain certificate", "file", filename, "err", err)
				continue
			}
			written[path] = struct{}{}
		}

		for _, signer := range signers {
			if err := kc.state.insertKey(signer); err != nil {
				log.Error(kc, "Failed to insert keychain key", "file", filename, "err", err)
				continue
			}
			secret, err := sig.MarshalSecret(signer)
			if err != nil {
				log.Error(kc, "Failed to marshal keychain key", "file", filename, "err", err)
				continue
			}
			path, err := kc.writeFile(secret.Join(), EXT_KEY)
			if err != nil {
				log.Error(kc, "Failed to persist keychain key", "file", filename, "err", err)
				continue
			}
			written[path] = struct{}{}
		}

		if len(written) > 0 {
			if _, ok := written[filename]; !ok {
				_ = os.Remove(filename)
			}
		}
	}

	return kc, nil
}

// (AI GENERATED DESCRIPTION): Returns a string representation of the KeyChainDir, displaying the path to the keychain directory.
func (kc *KeyChainDir) String() string {
	return fmt.Sprintf("keychain-dir (%s)", kc.path)
}

// (AI GENERATED DESCRIPTION): Returns the underlying in‑memory store that backs the KeyChainDir.
func (kc *KeyChainDir) Store() ndn.Store {
	return kc.state.pubStore
}

// (AI GENERATED DESCRIPTION): Returns a slice of all identities currently stored in the key‑chain directory.
func (kc *KeyChainDir) Identities() []ndn.KeyChainIdentity {
	return kc.state.Identities()
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the identity that matches the specified name from the keychain directory’s in‑memory store.
func (kc *KeyChainDir) IdentityByName(name enc.Name) ndn.KeyChainIdentity {
	return kc.state.IdentityByName(name)
}

// (AI GENERATED DESCRIPTION): Adds a signer to the in‑memory key chain and writes its secret key to disk in a file with the key extension.
func (kc *KeyChainDir) InsertKey(signer ndn.Signer) error {
	err := kc.state.insertKey(signer)
	if err != nil {
		return err
	}

	secret, err := sig.MarshalSecret(signer)
	if err != nil {
		return err
	}

	_, err = kc.writeFile(secret.Join(), EXT_KEY)
	return err
}

// (AI GENERATED DESCRIPTION): Inserts the given certificate (in wire format) into the in‑memory key chain and writes it to disk with the certificate file extension.
func (kc *KeyChainDir) InsertCert(wire []byte) error {
	err := kc.state.insertCert(wire)
	if err != nil {
		return err
	}

	_, err = kc.writeFile(wire, EXT_CERT)
	return err
}

// DeleteKey removes a key and its certificates from the keychain and disk.
func (kc *KeyChainDir) DeleteKey(keyName enc.Name) error {
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

	// collect certificate wires before removal
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

// DeleteCert removes a certificate from the keychain and disk.
func (kc *KeyChainDir) DeleteCert(name enc.Name) error {
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

// (AI GENERATED DESCRIPTION): Writes the given binary data to a PEM‑encoded file named after its SHA‑256 hash (plus the supplied extension) in the keychain directory, with permissions set to 0600.
func (kc *KeyChainDir) writeFile(wire []byte, ext string) (string, error) {
	hash := sha256.Sum256(wire)
	filename := hex.EncodeToString(hash[:]) + ext
	path := filepath.Join(kc.path, filename)

	str, err := sec.PemEncode(wire)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, str, 0600); err != nil {
		return "", err
	}

	kc.files[filename] = path
	kc.refs[path]++
	return path, nil
}

func (kc *KeyChainDir) deleteFile(wire []byte, ext string) error {
	hash := sha256.Sum256(wire)
	filename := hex.EncodeToString(hash[:]) + ext
	path, ok := kc.files[filename]
	if !ok {
		path = filepath.Join(kc.path, filename)
	}

	if count, ok := kc.refs[path]; ok {
		if count > 1 {
			kc.refs[path] = count - 1
			delete(kc.files, filename)
			return nil
		}
		delete(kc.refs, path)
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	delete(kc.files, filename)
	return nil
}
