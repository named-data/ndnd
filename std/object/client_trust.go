package object

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	rdr "github.com/named-data/ndnd/std/ndn/rdr_2024"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/signer"
)

// SuggestSigner returns the signer for a given name
// nil is returned if no signer is found
func (c *Client) SuggestSigner(name enc.Name) ndn.Signer {
	if c.trust == nil {
		return signer.AsContextSigner(signer.NewSha256Signer())
	}
	name = removeRdr(name)
	return signer.AsContextSigner(c.trust.Suggest(name))
}

// Validate a data packet using the client configuration
func (c *Client) Validate(data ndn.Data, sigCov enc.Wire, callback func(bool, error)) {
	c.ValidateExt(ndn.ValidateExtArgs{
		Data:       data,
		SigCovered: sigCov,
		Callback:   callback,
	})
}

// ValidateExt is an advanced API for validating data packets
func (c *Client) ValidateExt(args ndn.ValidateExtArgs) {
	if c.trust == nil {
		args.Callback(true, nil)
		return
	}

	// Pop off RDR naming convention components
	overrideName := removeRdr(args.Data.Name())
	if len(args.OverrideName) > 0 {
		overrideName = args.OverrideName
	}

	// Default fetch function
	fetch := args.Fetch.GetOr(func(name enc.Name, config *ndn.InterestConfig, callback ndn.ExpressCallbackFunc) {
		config.NextHopId = args.CertNextHop
		c.ExpressR(ndn.ExpressRArgs{
			Name:     name,
			Config:   config,
			Retries:  3,
			Callback: callback,
			TryStore: c.store,
		})
	})

	c.trust.Validate(sec.TrustConfigValidateArgs{
		Data:              args.Data,
		DataSigCov:        args.SigCovered,
		Callback:          args.Callback,
		OverrideName:      overrideName,
		UseDataNameFwHint: args.UseDataNameFwHint,
		IgnoreValidity:    args.IgnoreValidity,
		Fetch:             fetch,
	})
}

// SetTrustSchema replaces the client's trust schema at runtime.
// No-op if the client does not have a trust config or if schema is nil.
func (c *Client) SetTrustSchema(schema ndn.TrustSchema) {
	if c.trust == nil || schema == nil {
		return
	}
	c.trust.SetSchema(schema)
}

// PromoteTrustAnchor installs a validated trust anchor into the client's trust config.
// No-op if the client does not have a trust config.
func (c *Client) PromoteTrustAnchor(cert ndn.Data, raw enc.Wire) {
	if c.trust == nil {
		return
	}
	c.trust.PromoteAnchor(cert, raw)
}

// removeRdr removes the components from RDR naming convention
func removeRdr(name enc.Name) enc.Name {
	if name.At(-1).IsSegment() {
		name = name.Prefix(-1)
	}
	if name.At(-1).IsVersion() {
		name = name.Prefix(-1)
	}
	if name.At(-1).IsKeyword(rdr.MetadataKeyword) {
		name = name.Prefix(-1)
	}
	return name
}
