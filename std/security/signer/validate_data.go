package signer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// ValidateData verifies the signature of a Data packet with a certificate.
func ValidateData(data ndn.Data, sigCovered enc.Wire, cert ndn.Data) (bool, error) {
	return validateSignature(data.Signature(), sigCovered, cert.Content())
}

// ValidateInterest verifies the signature of an Interest packet with a certificate.
func ValidateInterest(interest ndn.Interest, sigCovered enc.Wire, cert ndn.Data) (bool, error) {
	return validateSignature(interest.Signature(), sigCovered, cert.Content())
}

func validateSignature(signature ndn.Signature, sigCovered enc.Wire, content enc.Wire) (bool, error) {
	switch signature.SigType() {
	case ndn.SignatureSha256WithRsa:
		pkey, err := x509.ParsePKIXPublicKey(content.Join())
		if err != nil {
			return false, err
		}
		if pub, ok := pkey.(*rsa.PublicKey); ok {
			return ValidateRsa(sigCovered, signature, pub), nil
		}
	case ndn.SignatureSha256WithEcdsa:
		pkey, err := x509.ParsePKIXPublicKey(content.Join())
		if err != nil {
			return false, err
		}
		if pub, ok := pkey.(*ecdsa.PublicKey); ok {
			return validateEcdsa(sigCovered, signature, pub), nil
		}
	case ndn.SignatureEd25519:
		pkey, err := x509.ParsePKIXPublicKey(content.Join())
		if err != nil {
			return false, err
		}
		if pub, ok := pkey.(ed25519.PublicKey); ok {
			return validateEd25519(sigCovered, signature, pub), nil
		}
	}

	return false, ndn.ErrInvalidValue{
		Item:  "Signature.SigType",
		Value: signature.SigType(),
	}
}
