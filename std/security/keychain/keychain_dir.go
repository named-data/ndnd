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
	mem  ndn.KeyChain
	path string
}

// NewKeyChainDir creates a new in-memory keychain.
func NewKeyChainDir(path string, pubStore ndn.Store) (ndn.KeyChain, error) {
	kc := &KeyChainDir{
		mem:  NewKeyChainMem(pubStore),
		path: path,
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
		content, err := os.ReadFile(filename)
		if err != nil {
			log.Warn(kc, "Failed to read keychain entry", "file", filename, "err", err)
			continue
		}

		err = InsertFile(kc.mem, content)
		if err != nil {
			log.Error(kc, "Failed to insert keychain entries", "file", filename, "err", err)
		}
	}

	return kc, nil
}

func (kc *KeyChainDir) String() string {
	return fmt.Sprintf("keychain-dir (%s)", kc.path)
}

func (kc *KeyChainDir) Store() ndn.Store {
	return kc.mem.Store()
}

func (kc *KeyChainDir) Identities() []ndn.KeyChainIdentity {
	return kc.mem.Identities()
}

func (kc *KeyChainDir) IdentityByName(name enc.Name) ndn.KeyChainIdentity {
	return kc.mem.IdentityByName(name)
}

func (kc *KeyChainDir) InsertKey(signer ndn.Signer) error {
	err := kc.mem.InsertKey(signer)
	if err != nil {
		return err
	}

	secret, err := sig.MarshalSecret(signer)
	if err != nil {
		return err
	}

	return kc.writeFile(secret.Join(), EXT_KEY)
}

func (kc *KeyChainDir) InsertCert(wire []byte) error {
	err := kc.mem.InsertCert(wire)
	if err != nil {
		return err
	}

	return kc.writeFile(wire, EXT_CERT)
}

func (kc *KeyChainDir) writeFile(wire []byte, ext string) error {
	hash := sha256.Sum256(wire)
	filename := hex.EncodeToString(hash[:])
	path := filepath.Join(kc.path, filename+ext)

	str, err := sec.PemEncode(wire)
	if err != nil {
		return err
	}

	return os.WriteFile(path, str, 0600)
}
