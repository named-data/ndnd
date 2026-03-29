package nac

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NAC utilities to construct and parse NDN names
//
// names look like:
//   encrypted content:  <content-name>/FOR/<ck-name>
//   encrypted CK:       <ck-name>/FOR/<kek-name>
//   encrypted KDK:      <kdk-name>/FOR/<consumer-key-name>

// KEKName: builds NDN name for kek => <credential-prefix>/E-KEY/<hex-key-id>
func KEKName(credentialPrefix string, keyID []byte) string {
	return credentialPrefix + "/E-KEY/" + hex.EncodeToString(keyID)
}

// KDKName: builds NDN name for kdk => <credential-prefix>/D-KEY/<hex-key-id>
func KDKName(credentialPrefix string, keyID []byte) string {
	return credentialPrefix + "/D-KEY/" + hex.EncodeToString(keyID)
}

// ContentKeyName: builds NDN name for a ck => <data-prefix>/CK/<hex-ck-id>
func ContentKeyName(dataPrefix string, ckID []byte) string {
	return dataPrefix + "/CK/" + hex.EncodeToString(ckID)
}

// EncryptedDataName: builds the /FOR/ formated name to link encrypted data to the key that encrypted it
func EncryptedDataName(contentName, encryptingKeyName string) string {
	return contentName + "/FOR/" + encryptingKeyName
}

// ConsumerKeyName: builds NDN name for consumer's identity key => <consumer-id>/KEY/<hex-key-id>
func ConsumerKeyName(consumerIdentity string, keyID []byte) string {
	return consumerIdentity + "/KEY/" + hex.EncodeToString(keyID)
}

// ParseEncryptedDataName: gets content name + encrypting key name
func ParseEncryptedDataName(name string) (contentName, keyName string, err error) {
	idx := strings.Index(name, "/FOR/")
	if idx == -1 {
		return "", "", fmt.Errorf("no /FOR/ in name: %s", name)
	}
	return name[:idx], name[idx+len("/FOR/"):], nil
}

// ParseKEKName: gets credential prefix + hex key id from a KEK name
func ParseKEKName(name string) (credentialPrefix, keyIDHex string, err error) {
	idx := strings.Index(name, "/E-KEY/")
	if idx == -1 {
		return "", "", fmt.Errorf("no /E-KEY/ in name: %s", name)
	}
	return name[:idx], name[idx+len("/E-KEY/"):], nil
}

// ParseKDKName: gets credential prefix + hex key id from a KDK name
func ParseKDKName(name string) (credentialPrefix, keyIDHex string, err error) {
	idx := strings.Index(name, "/D-KEY/")
	if idx == -1 {
		return "", "", fmt.Errorf("no /D-KEY/ in name: %s", name)
	}
	return name[:idx], name[idx+len("/D-KEY/"):], nil
}
