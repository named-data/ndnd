package security

import (
	"crypto/rand"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// MakeKeyName generates a new key name for a given identity.
func MakeKeyName(name enc.Name) enc.Name {
	keyId := make([]byte, 8)
	rand.Read(keyId)

	return name.
		Append(enc.NewGenericComponent("KEY")).
		Append(enc.NewGenericBytesComponent(keyId))
}

// GetIdentityFromKeyName extracts the identity name from a key name.
func GetIdentityFromKeyName(name enc.Name) (enc.Name, error) {
	if name.At(-2).String() != "KEY" {
		return nil, ndn.ErrInvalidValue{Item: "KEY component"}
	}
	return name.Prefix(-2), nil
}

// MakeCertName generates a new certificate name for a given key name.
func MakeCertName(keyName enc.Name, issuerId enc.Component, version uint64) (enc.Name, error) {
	_, err := GetIdentityFromKeyName(keyName) // Check if key name is valid
	if err != nil {
		return nil, err
	}
	return keyName.Append(issuerId, enc.NewVersionComponent(version)), nil
}

// GetKeyNameFromCertName extracts the key name from a certificate name.
func GetKeyNameFromCertName(name enc.Name) (enc.Name, error) {
	if name.At(-1).Typ == enc.TypeImplicitSha256DigestComponent {
		name = name.Prefix(-1)
	}
	if name.At(-4).String() != "KEY" {
		return nil, ndn.ErrInvalidValue{Item: "KEY component"}
	}
	return name.Prefix(-2), nil
}

// GetIdentityFromCertName extracts the identity name from a certificate name.
func GetIdentityFromCertName(name enc.Name) (enc.Name, error) {
	keyName, err := GetKeyNameFromCertName(name)
	if err != nil {
		return nil, err
	}
	return GetIdentityFromKeyName(keyName)
}

// CertListPrefix returns /<domain>/KEY/<keyid>/32=auth for the given key name.
func CertListPrefix(keyName enc.Name) (enc.Name, error) {
	if _, err := GetIdentityFromKeyName(keyName); err != nil {
		return nil, err
	}
	return keyName.Append(enc.NewKeywordComponent("auth")), nil
}

// CertListNameMatches checks whether the CertList name is under /<domain>/KEY/<keyid>/32=auth[/<version>].
func CertListNameMatches(keyName, listName enc.Name) bool {
	prefix, err := CertListPrefix(keyName)
	if err != nil {
		return false
	}
	listName = stripImplicitDigest(listName)
	if len(listName) < len(prefix) {
		return false
	}
	if !prefix.Equal(listName.Prefix(len(prefix))) {
		return false
	}
	rest := listName[len(prefix):]
	if len(rest) == 0 {
		return true
	}
	if len(rest) == 1 && rest[0].IsVersion() {
		return true
	}
	return false
}

// CertListVersion returns the version component on the CertList name, or zero if absent.
func CertListVersion(name enc.Name) uint64 {
	name = stripImplicitDigest(name)
	if name.At(-1).IsVersion() {
		return name.At(-1).NumberVal()
	}
	return 0
}

func stripImplicitDigest(name enc.Name) enc.Name {
	if name.At(-1).Typ == enc.TypeImplicitSha256DigestComponent {
		return name.Prefix(-1)
	}
	return name
}

// KeyNameFromLocator extracts /<identity>/KEY/<keyid> from a KeyLocator name
// that may be a key name, certificate name, or cert name without version.
func KeyNameFromLocator(name enc.Name) (enc.Name, error) {
	name = stripImplicitDigest(name)
	if len(name) < 3 {
		return nil, ndn.ErrInvalidValue{Item: "KEY component"}
	} else {
		for i := len(name) - 2; i >= 0; i-- {
			comp := name.At(i)
			if comp.String() == "KEY" || comp.IsKeyword("KEY") {
				return name[:i+2], nil
			}
		}
		return nil, ndn.ErrInvalidValue{Item: "KEY component"}
	}
}
