package security

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

// SignCertArgs are the arguments to SignCert.
type SignCertArgs struct {
	// Signer is the private key used to sign the certificate.
	Signer ndn.Signer
	// Data is the CSR or Key to be signed.
	Data ndn.Data
	// IssuerId is the issuer ID to be included in the certificate name.
	IssuerId enc.Component
	// NotBefore is the start of the certificate validity period.
	NotBefore time.Time
	// NotAfter is the end of the certificate validity period.
	NotAfter time.Time
	// Description is extra information to be included in the certificate.
	Description map[string]string
	// CrossSchema to attach to the certificate.
	CrossSchema enc.Wire
}

// SignCert signs a new NDN certificate with the given signer.
// Data must have either a Key or Secret in the Content.
func SignCert(args SignCertArgs) (enc.Wire, error) {
	// Check all parameters (strict for certs)
	if args.Signer == nil || args.Data == nil || args.IssuerId.Typ == 0 {
		return nil, ndn.ErrInvalidValue{Item: "SignCertArgs", Value: args}
	}
	if args.NotBefore.IsZero() || args.NotAfter.IsZero() {
		return nil, ndn.ErrInvalidValue{Item: "Validity", Value: args}
	}

	// Cannot expire before it starts
	if args.NotAfter.Before(args.NotBefore) {
		return nil, ndn.ErrInvalidValue{Item: "Expiry", Value: args.NotAfter}
	}

	// Get public key bits and key name
	pk, keyName, err := getPubKey(args.Data)
	if err != nil {
		return nil, err
	}

	// Get certificate name
	certName, err := MakeCertName(keyName, args.IssuerId, uint64(time.Now().UnixMilli()))
	if err != nil {
		return nil, err
	}

	// TODO: set description
	// Create certificate data
	cfg := &ndn.DataConfig{
		ContentType:  optional.Some(ndn.ContentTypeKey),
		Freshness:    optional.Some(time.Hour),
		SigNotBefore: optional.Some(args.NotBefore),
		SigNotAfter:  optional.Some(args.NotAfter),
		CrossSchema:  args.CrossSchema,
	}
	cert, err := spec.Spec{}.MakeData(certName, cfg, enc.Wire{pk}, args.Signer)
	if err != nil {
		return nil, err
	}

	return cert.Wire, nil
}

// SelfSign generates a self-signed certificate.
func SelfSign(args SignCertArgs) (wire enc.Wire, err error) {
	if args.Data != nil {
		return nil, ndn.ErrInvalidValue{Item: "SelfSign.args.Data", Value: args.Data}
	}
	if args.Signer == nil {
		return nil, ndn.ErrInvalidValue{Item: "SelfSign.args.Signer", Value: args.Signer}
	}
	if args.IssuerId.Typ == 0 {
		args.IssuerId = enc.NewGenericComponent("self")
	}

	args.Data, err = sig.MarshalSecretToData(args.Signer)
	if err != nil {
		return nil, err
	}

	return SignCert(args)
}

func CertIsExpired(cert ndn.Data) bool {
	if cert.Signature() == nil {
		return true
	}

	now := time.Now()
	notBefore, notAfter := cert.Signature().Validity()
	if val, ok := notBefore.Get(); !ok || now.Before(val) {
		return true
	}
	if val, ok := notAfter.Get(); !ok || now.After(val) {
		return true
	}

	return false
}

// getPubKey gets the public key from an NDN data.
// returns [public key, key name, error].
func getPubKey(data ndn.Data) ([]byte, enc.Name, error) {
	contentType, ok := data.ContentType().Get()
	if !ok {
		return nil, nil, ndn.ErrInvalidValue{Item: "Data.ContentType", Value: nil}
	}

	switch contentType {
	case ndn.ContentTypeKey:
		// Content is public key, return directly
		pub := data.Content().Join()
		keyName, err := GetKeyNameFromCertName(data.Name())
		if err != nil {
			return nil, nil, err
		}
		return pub, keyName, nil
	case ndn.ContentTypeSigningKey:
		// Content is private key, parse the signer
		signer, err := sig.UnmarshalSecret(data)
		if err != nil {
			return nil, nil, err
		}
		pub, err := signer.Public()
		if err != nil {
			return nil, nil, err
		}
		return pub, signer.KeyName(), nil
	default:
		// Invalid content type
		return nil, nil, ndn.ErrInvalidValue{Item: "Data.ContentType", Value: contentType}
	}
}
