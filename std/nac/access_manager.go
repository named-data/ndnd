package nac

import (
	"crypto/ecdh"
	"strings"
)

// AccessManager controls read access for a namespace.
// Generates KEK/KDK pair, publishes KEK openly, distributes per-consumer encrypted KDKs.
// ref: https://named-data.net/wp-content/uploads/2016/02/ndn-0034-2-nac.pdf - 4.4.2 pg 6
type AccessManager struct {
	accessPrefix string
	dataset      string
	kek          *KeyEncryptionKey
	kdk          *KeyDecryptionKey
	members      map[string][]byte // consumer keyname -> encrypted KDK bytes
}

// NewAccessManager creates an access manager for <accessPrefix>/NAC/<dataset>.
func NewAccessManager(accessPrefix, dataset string) (*AccessManager, error) {
	kek, kdk, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	return &AccessManager{
		accessPrefix: accessPrefix,
		dataset:      dataset,
		kek:          kek,
		kdk:          kdk,
		members:      make(map[string][]byte),
	}, nil
}

func (am *AccessManager) KEK() *KeyEncryptionKey {
	return am.kek
}

func (am *AccessManager) AccessPrefix() string {
	return am.accessPrefix
}

func (am *AccessManager) Dataset() string {
	return am.dataset
}

func (am *AccessManager) KDKID() []byte {
	return am.kdk.ID
}

func normalizeKeyName(name string) string {
	return strings.TrimPrefix(name, "/")
}

// AddMember authorizes a consumer to decrypt content under this namespace.
func (am *AccessManager) AddMember(consumerKeyName string, consumerPubKey *ecdh.PublicKey) error {
	consumerKeyName = normalizeKeyName(consumerKeyName)
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

// GetEncryptedKDK returns encrypted KDK blob for a consumer, or (nil, false) if unauthorized.
func (am *AccessManager) GetEncryptedKDK(consumerKeyName string) ([]byte, bool) {
	blob, ok := am.members[normalizeKeyName(consumerKeyName)]
	return blob, ok
}

// GetEncryptedKDKName: <access-prefix>/NAC/<dataset>/KDK/<key-id>/ENCRYPTED-BY/<consumer-key-name>
func (am *AccessManager) GetEncryptedKDKName(consumerKeyName string) string {
	return EncryptedKDKName(am.accessPrefix, am.dataset, am.kdk.ID, normalizeKeyName(consumerKeyName))
}

// IsAuthorized checks if a consumer has been added as a member.
func (am *AccessManager) IsAuthorized(consumerKeyName string) bool {
	_, ok := am.members[normalizeKeyName(consumerKeyName)]
	return ok
}
