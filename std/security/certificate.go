package security

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	revocationtlv "github.com/named-data/ndnd/std/security/revocation_tlv"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

type revocationReason uint64

const revocationReasonUnspecified revocationReason = 0

const defaultRevocationFreshness = 8760 * time.Hour

// RevokeCertArgs are the arguments to RevokeCert.
type RevokeCertArgs struct {
	// Cert is the certificate being revoked.
	Cert ndn.Data
	// Signer signs the revocation record Data packet. May be nil for unsigned records.
	Signer ndn.Signer
	// Reason is the revocation reason code.
	Reason revocationReason
	// Timestamp is the revocation timestamp. Defaults to now.
	Timestamp optional.Optional[time.Time]
	// NotBefore marks data produced before this timestamp as still valid.
	NotBefore optional.Optional[time.Time]
	// Freshness is the FreshnessPeriod of the record Data packet.
	Freshness optional.Optional[time.Duration]
}

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
	signer := sig.AsContextSigner(args.Signer)

	cert, err := spec.Spec{}.MakeData(certName, cfg, enc.Wire{pk}, signer)
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

// CertIsExpired reports whether the certificate is outside its validity period.
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

// RevokeCert builds a signed revocation record Data packet for a certificate.
func RevokeCert(args RevokeCertArgs) (enc.Wire, error) {
	if args.Cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	recordName, ok := revocationRecordName(args.Cert)
	if !ok {
		return nil, fmt.Errorf("invalid certificate name for revocation: %s", args.Cert.Name())
	}

	timestamp := args.Timestamp.GetOr(time.Now())
	hash := sha256.Sum256(args.Cert.Content().Join())
	record := revocationtlv.RevocationRecord{
		Timestamp:     uint64(timestamp.UnixMilli()),
		Reason:        uint64(args.Reason),
		PublicKeyHash: hash[:],
	}
	if nb, ok := args.NotBefore.Get(); ok {
		record.NotBefore = optional.Some(uint64(nb.UnixMilli()))
	}

	cfg := &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeKey),
		Freshness:   optional.Some(args.Freshness.GetOr(defaultRevocationFreshness)),
	}

	encoded, err := spec.Spec{}.MakeData(recordName, cfg, record.Encode(), args.Signer)
	if err != nil {
		return nil, err
	}

	return encoded.Wire, nil
}

func revocationRecordName(cert ndn.Data) (enc.Name, bool) {
	if cert == nil {
		return nil, false
	}

	certName := stripImplicitDigest(cert.Name())
	identity, err := GetIdentityFromCertName(certName)
	if err != nil || !certName.At(-1).IsVersion() {
		return nil, false
	}

	recordName := make(enc.Name, len(certName), len(certName)+1)
	copy(recordName, certName)
	recordName[len(identity)] = enc.NewGenericComponent("REVOKE")
	return recordName.Append(certName.At(-2)), true
}

func isRevocationRecordName(name enc.Name) bool {
	name = stripImplicitDigest(name)
	if len(name) < 6 || name.At(-1).Typ != enc.TypeGenericNameComponent || !name.At(-2).IsVersion() {
		return false
	}

	certName := make(enc.Name, len(name)-1)
	copy(certName, name.Prefix(-1))
	certName[len(name)-5] = enc.NewGenericComponent("KEY")

	_, err := GetIdentityFromCertName(certName)
	return err == nil
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

// EncodeCertList encodes a list of certificate names as a TLV sequence of Name TLVs.
func EncodeCertList(names []enc.Name) (enc.Wire, error) {
	if len(names) == 0 {
		return nil, ndn.ErrInvalidValue{Item: "CertList", Value: "empty"}
	}
	length := 0
	for _, n := range names {
		length += len(n.Bytes())
	}
	buf := make([]byte, length)
	pos := 0
	for _, n := range names {
		nb := n.Bytes()
		copy(buf[pos:], nb)
		pos += len(nb)
	}
	return enc.Wire{buf}, nil
}

// DecodeCertList decodes the content of a CertList into certificate names.
func DecodeCertList(content enc.Wire) ([]enc.Name, error) {
	reader := enc.NewWireView(content)
	names := make([]enc.Name, 0)
	for !reader.IsEOF() {
		typ, err := reader.ReadTLNum()
		if err != nil {
			return nil, err
		}
		l, err := reader.ReadTLNum()
		if err != nil {
			return nil, err
		}
		if typ != enc.TypeName {
			return nil, fmt.Errorf("unexpected TLV type %x in CertList", typ)
		}
		nameView := reader.Delegate(int(l))
		if nameView.Length() != int(l) {
			return nil, io.ErrUnexpectedEOF
		}
		name, err := nameView.ReadName()
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, ndn.ErrInvalidValue{Item: "CertList", Value: "empty"}
	}
	return names, nil
}
