package keychain

import (
	"net/url"

	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
)

// (AI GENERATED DESCRIPTION): Creates a new keychain instance from the given URI, selecting either an in‑memory or directory‑based implementation based on the URI scheme and attaching the supplied public key store, returning an error for unsupported schemes.
func NewKeyChain(uri string, pubStore ndn.Store) (ndn.KeyChain, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	switch url.Scheme {
	case "mem":
		return NewKeyChainMem(pubStore), nil
	case "dir":
		return NewKeyChainDir(url.Path, pubStore)
	default:
		return nil, ndn.ErrInvalidValue{Item: "keychain-scheme", Value: url.Scheme}
	}
}

// InsertFile inserts all signers and certs from the given content.
func InsertFile(kc ndn.KeyChain, content []byte) error {
	signers, certs, err := sec.DecodeFile(content)
	if err != nil {
		return err
	}

	for _, wire := range certs {
		if err := kc.InsertCert(wire); err != nil {
			log.Warn(kc, "Failed to insert certificate", "err", err)
			continue
		}
	}

	for _, signer := range signers {
		if err := kc.InsertKey(signer); err != nil {
			log.Warn(kc, "Failed to insert key", "err", err)
			continue
		}
	}

	return nil
}
