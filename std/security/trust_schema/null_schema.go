package trust_schema

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/security/signer"
)

// NullSchema is a trust schema that allows everything.
type NullSchema struct{}

// (AI GENERATED DESCRIPTION): Creates a new NullSchema object initialized with zero/default values.
func NewNullSchema() *NullSchema {
	return &NullSchema{}
}

// (AI GENERATED DESCRIPTION): Always returns true, meaning any packet and certificate pair is considered valid (no actual check is performed).
func (*NullSchema) Check(pkt enc.Name, cert enc.Name) bool {
	return true
}

// (AI GENERATED DESCRIPTION): Returns a new SHA‑256 signer, ignoring the provided name and key chain.
func (*NullSchema) Suggest(enc.Name, ndn.KeyChain) ndn.Signer {
	return signer.NewSha256Signer()
}
