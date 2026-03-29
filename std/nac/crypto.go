package nac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// info string for HKDF - needs to match on encrypt/decrypt
// "optional but highly recommended input that serves to bind the derived key material to specific application and context information"
// https://crypto.stackexchange.com/questions/6553/what-information-to-include-is-the-info-input-for-hkdf#:~:text=While%20the%20'info'%20value%20is,input%20key%20material%20value%20IKM.
var hkdfInfo = []byte("NAC-ECIES-v1")

// SymEncrypt: encrypts plaintext with AES-256-GCM
// key must be exactly 32 bytes (bc 256 bits)
// returns: (below is concat return)
//
//	[12-byte nonce][ciphertext][16-byte GCM auth tag]
//
// ref: https://pkg.go.dev/crypto/cipher#NewGCM
func SymEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// fresh nonce for fresh encryption
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	// Note: gcm.Seal appends ciphertext+tag to dst ==> passing nonce as dst the nonce gets prepended to the output
	// result:
	//
	// 			[nonce][ciphertext][tag]
	//
	// ref: https://pkg.go.dev/crypto/cipher#AEAD.Seal
	out := gcm.Seal(nonce, nonce, plaintext, nil)
	return out, nil
}

// SymDecrypt: decrypt AES-256-GCM ciphertex, key should be 32 bytes, ciphertext must be output of SymEncrypt (nonce + encrypted data + tag)
func SymDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize() // 12
	if len(ciphertext) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	enc := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, enc, nil)
	if err != nil {
		// gcm auth tag verification failed == data tampered/wrong key
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

// AsymEncrypt: encrypts plaintext w/ ECIES (X25519 +HKDF + AES-GCM)
//
//	pub: recipient's X25519 pub key
//	plaintext: arbitrary length data to encrypt
//
// ECIES will (https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme):
//  1. gen ephemeral X25519 key pair
//  2. ECDH(ephemeral private, recipient public) -> shared secret
//  3. HKDF(shared secret) -> 32-byte AES key
//  4. SymEncrypt(plaintext) using derived AES key
//  5. return: [32-byte ephemeral public key][encrypted data]
//
// output:
//
//	[ephemeral_pub_key][nonce+ciphertext+tag from SymEncrypt]
func AsymEncrypt(pub *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	// generate ephemeral key pair
	curve := ecdh.X25519()
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPub := ephemeralPriv.PublicKey()

	// ECDH  get shared secret
	sharedSecret, err := ephemeralPriv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// AES key from shared secret using HKDF
	//https://pkg.go.dev/golang.org/x/crypto/hkdf
	kdf := hkdf.New(sha256.New, sharedSecret, nil, hkdfInfo)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	// encrypt plaintext
	encData, err := SymEncrypt(aesKey, plaintext)
	if err != nil {
		return nil, err
	}

	// prepend pub key to ciphertext
	result := append(ephemeralPub.Bytes(), encData...)
	return result, nil
}

// AsymDecrypt: decrypts ECIES ciphertext
//
//	priv: recipient's X25519 private key
//	ciphertext: output from AsymEncrypt
//
// ...basically just reverse of AsymEncrypt:
//  1. get first 32 bytes (ephemeral pub key)
//  2. ECDH(recipient private, ephemeral public) -> shared secret
//  3. HKDF(shared secret) -> AES key
//  4. SymDecrypt(remaining bytes) w/ AES key
func AsymDecrypt(priv *ecdh.PrivateKey, ciphertext []byte) ([]byte, error) {
	// get public key
	if len(ciphertext) < 32 {
		return nil, fmt.Errorf("ciphertext too short (need at least 32 bytes for ephemeral key)")
	}
	ephemeralPubBytes := ciphertext[:32]
	encData := ciphertext[32:]
	curve := ecdh.X25519()
	ephemeralPub, err := curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// get shared secret (should be same as what encrypt got)
	sharedSecret, err := priv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// get AES key from shared secret w/ HKDF
	// NOTE: must use same parameters as AsymEncrypt (nil is the salt, info=hkdfInfo)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, hkdfInfo)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	// fmt.Printf("derived aes key len=%d\n", len(aesKey))

	// decrypt data w/ AES key
	plaintext, err := SymDecrypt(aesKey, encData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
