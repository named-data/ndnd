package nac

import (
	"crypto/ecdh"
	"fmt"
)

// Decryptor: chain is
//
//	encKDK blob  ->  AsymDecrypt(consumer key)  ->  KDK
//	encCK payload  ->  AsymDecrypt(KDK)  ->  CK (32 byte AES key)
//	encContent payload  ->  SymDecrypt(CK)  ->  plaintext
type Decryptor struct {
	consumerKeyName string           // consumer's NDN identity name
	privateKey      *ecdh.PrivateKey // consumer's X25519 private key
}

// NewDecryptor: creates decryptor for a consumer
func NewDecryptor(consumerKeyName string, privateKey *ecdh.PrivateKey) *Decryptor {
	return &Decryptor{
		consumerKeyName: consumerKeyName,
		privateKey:      privateKey,
	}
}

// Decrypt: runs full decryption chain (fig 13)
//
//	(encContent+encCK would be fetched via NDN Interests, encKDKBlob from access manager)
func (d *Decryptor) Decrypt(
	encContent *EncryptedContent,
	encCK *EncryptedCK,
	encKDKBlob []byte,
) ([]byte, error) {
	// decrypt KDK w/ consumer's private key
	kdkBytes, err := AsymDecrypt(d.privateKey, encKDKBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt KDK: %w", err)
	}

	// deserialize KDK -> X25519 private key
	kdk, err := DeserializePrivateKey(kdkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize KDK: %w", err)
	}
	// fmt.Printf("KDK, len=%d\n", len(kdkBytes))

	// decrypt content key w/ KDK
	ckKey, err := AsymDecrypt(kdk, encCK.EncryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CK: %w", err)
	}
	// fmt.Printf("CK, len=%d\n", len(ckKey))
	// decrypt content w/ CK
	plaintext, err := SymDecrypt(ckKey, encContent.EncryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}
	return plaintext, nil
}

// CKNameFromContent: gets CK name from encrypted content packet
//
//	consumer uses this to build the Interest for fetching the encrypted CK
func CKNameFromContent(encContent *EncryptedContent) (string, error) {
	_, ckName, err := ParseEncryptedDataName(encContent.Name)
	return ckName, err
}

// KDKNameForConsumer: constructs NDN name of the encrypted KDK this consumer should fetch
// result: <kdk-name>/FOR/<consumer-key-name>
func (d *Decryptor) KDKNameForConsumer(credentialPrefix string, kdkKeyID []byte) string {
	kdkName := KDKName(credentialPrefix, kdkKeyID)
	return EncryptedDataName(kdkName, d.consumerKeyName)
}
