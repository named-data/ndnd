package trust_schema

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/security/signer"
)

// NullSchema is a trust schema that allows everything.
type NullSchema struct{}

func NewNullSchema() *NullSchema {
	return &NullSchema{}
}

func (*NullSchema) Check(pkt enc.Name, cert enc.Name) bool {
	return true
}

func (*NullSchema) Suggest(enc.Name, ndn.KeyChain) ndn.Signer {
	return signer.NewSha256Signer()
}
