package nac

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NAC naming conventions (aligned with NAC spec):
//
//   KEK:       <access-prefix>/NAC/<dataset>/KEK/<key-id>
//   KDK:       <access-prefix>/NAC/<dataset>/KDK/<key-id>/ENCRYPTED-BY/<member-key-name>
//   CK:        <data-prefix>/CK/<ck-id>/ENCRYPTED-BY/<access-prefix>/NAC/<dataset>/KEK/<key-id>
//   content:   <content-name> (encrypted payload, CK name embedded in TLV)

// KEKName: <access-prefix>/NAC/<dataset>/KEK/<hex-key-id>
func KEKName(accessPrefix, dataset string, keyID []byte) string {
	return accessPrefix + "/NAC/" + dataset + "/KEK/" + hex.EncodeToString(keyID)
}

// KDKName: <access-prefix>/NAC/<dataset>/KDK/<hex-key-id>
func KDKName(accessPrefix, dataset string, keyID []byte) string {
	return accessPrefix + "/NAC/" + dataset + "/KDK/" + hex.EncodeToString(keyID)
}

// EncryptedKDKName: <access-prefix>/NAC/<dataset>/KDK/<key-id>/ENCRYPTED-BY/<member-key-name>
func EncryptedKDKName(accessPrefix, dataset string, keyID []byte, memberKeyName string) string {
	return KDKName(accessPrefix, dataset, keyID) + "/ENCRYPTED-BY/" + strings.TrimPrefix(memberKeyName, "/")
}

// ContentKeyName: <data-prefix>/CK/<hex-ck-id>
func ContentKeyName(dataPrefix string, ckID []byte) string {
	return dataPrefix + "/CK/" + hex.EncodeToString(ckID)
}

// CKEncryptedName: <data-prefix>/CK/<ck-id>/ENCRYPTED-BY/<kek-name>
func CKEncryptedName(dataPrefix string, ckID []byte, kekName string) string {
	return ContentKeyName(dataPrefix, ckID) + "/ENCRYPTED-BY/" + strings.TrimPrefix(kekName, "/")
}

// ConsumerKeyName: <consumer-id>/KEY/<hex-key-id>
func ConsumerKeyName(consumerIdentity string, keyID []byte) string {
	return consumerIdentity + "/KEY/" + hex.EncodeToString(keyID)
}

// ParseEncryptedByName: splits on /ENCRYPTED-BY/
func ParseEncryptedByName(name string) (baseName, keyName string, err error) {
	idx := strings.Index(name, "/ENCRYPTED-BY/")
	if idx == -1 {
		return "", "", fmt.Errorf("no /ENCRYPTED-BY/ in name: %s", name)
	}
	return name[:idx], name[idx+len("/ENCRYPTED-BY/"):], nil
}

// ParseKEKName: extracts access prefix, dataset, and key ID from a KEK name
func ParseKEKName(name string) (accessPrefix, dataset, keyIDHex string, err error) {
	nacIdx := strings.Index(name, "/NAC/")
	if nacIdx == -1 {
		return "", "", "", fmt.Errorf("no /NAC/ in name: %s", name)
	}
	rest := name[nacIdx+len("/NAC/"):]
	kekIdx := strings.Index(rest, "/KEK/")
	if kekIdx == -1 {
		return "", "", "", fmt.Errorf("no /KEK/ in name: %s", name)
	}
	return name[:nacIdx], rest[:kekIdx], rest[kekIdx+len("/KEK/"):], nil
}

// ParseKDKName: extracts access prefix, dataset, and key ID from a KDK name
func ParseKDKName(name string) (accessPrefix, dataset, keyIDHex string, err error) {
	nacIdx := strings.Index(name, "/NAC/")
	if nacIdx == -1 {
		return "", "", "", fmt.Errorf("no /NAC/ in name: %s", name)
	}
	rest := name[nacIdx+len("/NAC/"):]
	kdkIdx := strings.Index(rest, "/KDK/")
	if kdkIdx == -1 {
		return "", "", "", fmt.Errorf("no /KDK/ in name: %s", name)
	}
	return name[:nacIdx], rest[:kdkIdx], rest[kdkIdx+len("/KDK/"):], nil
}
