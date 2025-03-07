package trust_schema

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

type SignCrossSchemaArgs struct {
	// Name is the name of the trust schema.
	Name enc.Name
	// Signer is the private key used to sign the certificate.
	Signer ndn.Signer
	// Content is the trust schema to be signed.
	Content CrossSchemaContent
	// NotBefore is the start of the certificate validity period.
	NotBefore time.Time
	// NotAfter is the end of the certificate validity period.
	NotAfter time.Time
}

func SignCrossSchema(args SignCrossSchemaArgs) (enc.Wire, error) {
	// Check all parameters
	if args.Signer == nil || args.Name == nil {
		return nil, ndn.ErrInvalidValue{Item: "SignCrossSchemaArgs", Value: args}
	}
	if args.NotBefore.IsZero() || args.NotAfter.IsZero() {
		return nil, ndn.ErrInvalidValue{Item: "Validity", Value: args}
	}

	// Cannot expire before it starts
	if args.NotAfter.Before(args.NotBefore) {
		return nil, ndn.ErrInvalidValue{Item: "Expiry", Value: args.NotAfter}
	}

	// Make sure name has a version
	if !args.Name.At(-1).IsVersion() {
		return nil, fmt.Errorf("cross schema name must have a version")
	}

	// Create schema data
	cfg := &ndn.DataConfig{
		SigNotBefore: optional.Some(args.NotBefore),
		SigNotAfter:  optional.Some(args.NotAfter),
	}
	cs, err := spec.Spec{}.MakeData(args.Name, cfg, args.Content.Encode(), args.Signer)
	if err != nil {
		return nil, err
	}

	return cs.Wire, nil
}

func (cross *CrossSchemaContent) Match(dataName enc.Name, certName enc.Name) bool {
	for _, rule := range cross.SimpleSchemaRules {
		if rule.NamePrefix == nil || rule.KeyLocator == nil || rule.KeyLocator.Name == nil {
			continue
		}

		if !rule.NamePrefix.IsPrefix(dataName) {
			continue
		}

		if rule.KeyLocator.Name.IsPrefix(certName) {
			return true
		}
	}

	for _, rule := range cross.PrefixSchemaRules {
		if rule.NamePrefix == nil {
			continue
		}

		if !rule.NamePrefix.IsPrefix(dataName) {
			continue
		}

		// /keyName/KEY/kid/iss/ver
		if certName.Prefix(-4).IsPrefix(dataName[len(rule.NamePrefix):]) {
			return true
		}
	}

	return false
}
