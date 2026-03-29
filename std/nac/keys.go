package nac

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

// ContentKey: symmetric key to encrypt actual file content w/ a fresh one generated for each file
type ContentKey struct {
	ID  []byte // 16 random bytes which becomes part of the NDN name
	Key []byte // 32-byte AES-256 key
}

// KeyEncryptionKey: X25519 pub key tobe published by Access Manager, producers fetch this so they can wrap Content Keys w/ ECIES
// NOTE: NDN name pattern is /<credential-prefix>/E-KEY/<hex(ID)>
// https://named-data.net/wp-content/uploads/2016/02/ndn-0034-2-nac.pdf - pg 6
type KeyEncryptionKey struct {
	ID        []byte          // 16 random bytes
	PublicKey *ecdh.PublicKey // 32 byte X25519 pub key
}

// KeyDecryptionKey: X25519 private key held by the Access Manager, NEVER published in plaintext (encrypted per-consumer w/ AsymEncrypt (ECIES))
// NDN name pattern: /<credential-prefix>/D-KEY/<hex(ID)>
// https://named-data.net/wp-content/uploads/2016/02/ndn-0034-2-nac.pdf - pg 6
type KeyDecryptionKey struct {
	ID         []byte           // same ID as corresponding KEK
	PrivateKey *ecdh.PrivateKey // 32 byte X25519 private key
}

// NewContentKey: generates fresh Content Key with random ID + key material
func NewContentKey() (*ContentKey, error) {
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return nil, fmt.Errorf("failed to generate content key ID: %w", err)
	}
	key := make([]byte, 32) // AES-256 needs 32 bytes
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("couldn't generate content key: %w", err)
	}

	return &ContentKey{
		ID:  id,
		Key: key,
	}, nil
}

// NewKeyPair: generates X25519 key pair and wraps as KEK+KDK, both share the same ID
func NewKeyPair() (*KeyEncryptionKey, *KeyDecryptionKey, error) {
	// gen X25519 key pair
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 key pair: %w", err)
	}

	// gen random ID (shared by KEK+KDK)
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return nil, nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	kek := &KeyEncryptionKey{
		ID:        id,
		PublicKey: privateKey.PublicKey(),
	}
	kdk := &KeyDecryptionKey{
		ID:         id,
		PrivateKey: privateKey,
	}

	return kek, kdk, nil
}

// TODO: remove
// SerializePublicKey: encodes X25519 pub key to bytes (32 bytes) (this is a noop leftover from RSA impl, X25519 is alr 32B) - use this when publishing KEK as an NDN Data packet
func SerializePublicKey(pub *ecdh.PublicKey) ([]byte, error) {
	return pub.Bytes(), nil
}

// DeserializePublicKey: decode bytes to X25519 pub key
func DeserializePublicKey(keyBytes []byte) (*ecdh.PublicKey, error) {
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid public key length: got %d bytes, expected 32", len(keyBytes))
	}
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}
	return pub, nil
}

// SerializePrivateKey: encode a X25519 private key to bytes (32 bytes) (this is a noop leftover from RSA impl, X25519 is alr 32B) - idea was to use this before AsymEncrypt when distributing KDK to consumers
func SerializePrivateKey(priv *ecdh.PrivateKey) ([]byte, error) {
	return priv.Bytes(), nil
}

// DeserializePrivateKey: decode bytes to X25519 private key
func DeserializePrivateKey(keyBytes []byte) (*ecdh.PrivateKey, error) {
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: got %d bytes, expected 32", len(keyBytes))
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}
	return priv, nil
}

// TODO: do we need to convert keys -> hex for NDN names later??
// 		later we'll want ot build ndn names we should prob be using hex instead of raw bytes...
