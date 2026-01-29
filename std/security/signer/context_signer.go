package signer

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// ContextSigner implements ndn.Signer while overriding the key locator.
type ContextSigner struct {
	base           ndn.Signer
	KeyLocatorName enc.Name
}

// AsContextSigner wraps a signer into a ContextSigner. If already a ContextSigner with
// a non-empty KeyLocatorName, it is returned as-is; otherwise KeyLocatorName defaults
// to the signer's key name.
func AsContextSigner(s ndn.Signer) ndn.Signer {
	if s == nil {
		return nil
	}
	if cs, ok := s.(*ContextSigner); ok && len(cs.KeyLocatorName) > 0 {
		return cs
	}
	return &ContextSigner{
		base:           s,
		KeyLocatorName: s.KeyName(),
	}
}

// WithKeyLocator ensures signer is a ContextSigner and overrides its KeyLocatorName.
func WithKeyLocator(s ndn.Signer, keyLocator enc.Name) ndn.Signer {
	if s == nil {
		return nil
	}
	cs, ok := AsContextSigner(s).(*ContextSigner)
	if !ok {
		return nil
	}
	if len(keyLocator) > 0 {
		cs.KeyLocatorName = keyLocator
	}
	return cs
}

func (s *ContextSigner) Type() ndn.SigType {
	return s.base.Type()
}

func (s *ContextSigner) KeyName() enc.Name {
	return s.base.KeyName()
}

func (s *ContextSigner) KeyLocator() enc.Name {
	if len(s.KeyLocatorName) > 0 {
		return s.KeyLocatorName
	}
	return s.base.KeyLocator()
}

func (s *ContextSigner) EstimateSize() uint {
	return s.base.EstimateSize()
}

func (s *ContextSigner) Sign(wire enc.Wire) ([]byte, error) {
	return s.base.Sign(wire)
}

func (s *ContextSigner) Public() ([]byte, error) {
	return s.base.Public()
}
