package nac

import "crypto/ecdh"

// AccessManager: controls read access for a credential namespace
// idk if this lives on system controller, producer, or what but there must be some entity that gens the KEK/KDK pair, holds the KDK private keys, allows producers to fetch KEK and consumers to fetch encrpyted KDK
// it does:
//   - gens KEK/KDK pair
//   - publishes KEK openly
//   - distributes per consumer encrypted KDKs
//
// https://named-data.net/wp-content/uploads/2016/02/ndn-0034-2-nac.pdf - 4.4.2 pg 6
type AccessManager struct {
	credentialPrefix string
	kek              *KeyEncryptionKey
	kdk              *KeyDecryptionKey
	members          map[string][]byte // consumer keyname ->encrypted KDK bytes
}

// NewAccessManager: creates access manager
func NewAccessManager(credentialPrefix string) (*AccessManager, error) {
	kek, kdk, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	return &AccessManager{
		credentialPrefix: credentialPrefix,
		kek:              kek,
		kdk:              kdk,
		members:          make(map[string][]byte),
	}, nil
}

// KEK: returns pub encryption key
func (am *AccessManager) KEK() *KeyEncryptionKey {
	return am.kek
}

// CredentialPrefix: returns NDN credential prefix
func (am *AccessManager) CredentialPrefix() string {
	return am.credentialPrefix
}

// AddMember: auths a consumer to decrypt content under this credential
func (am *AccessManager) AddMember(consumerKeyName string, consumerPubKey *ecdh.PublicKey) error {
	kdkBytes, err := SerializePrivateKey(am.kdk.PrivateKey)
	if err != nil {
		return err
	}

	// ECIES-encrypt w/ consumers pub key
	encKDK, err := AsymEncrypt(consumerPubKey, kdkBytes)
	if err != nil {
		return err
	}
	// fmt.Printf("added member %s, encKDK len=%d\n", consumerKeyName, len(encKDK))
	am.members[consumerKeyName] = encKDK
	return nil
}

// GetEncryptedKDK: returns encrypted KDK blob for a consumer OR (nil, false) if  unauthorized
func (am *AccessManager) GetEncryptedKDK(consumerKeyName string) ([]byte, bool) {
	blob, ok := am.members[consumerKeyName]
	return blob, ok
}

// GetEncryptedKDKName: NDN name for a consumer's  KDK packet -> <kdk-name>/FOR/<consumerKeyName>
// (pg 7)
func (am *AccessManager) GetEncryptedKDKName(consumerKeyName string) string {
	kdkName := KDKName(am.credentialPrefix, am.kdk.ID)
	return EncryptedDataName(kdkName, consumerKeyName)
}

// IsAuthorized: has a consumer been added as a member?
func (am *AccessManager) IsAuthorized(consumerKeyName string) bool {
	_, ok := am.members[consumerKeyName]
	return ok
}
