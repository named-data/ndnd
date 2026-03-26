package nac

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestNewKeyPair(t *testing.T) {
	kek, kdk, err := NewKeyPair()
	if err != nil {
		t.Fatalf("NewKeyPair failed: %v", err)
	}
	if !bytes.Equal(kek.ID, kdk.ID) {
		t.Error("KEK and KDK should share the same ID")
	}
	if len(kek.ID) != 16 {
		t.Errorf("Expected 16-byte ID, got %d", len(kek.ID))
	}
	if kek.PublicKey == nil || kdk.PrivateKey == nil {
		t.Error("Keys should not be nil")
	}
}

func TestSymEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("hello NAC world, this is a test of AES-256-GCM encryption")
	ciphertext, err := SymEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("SymEncrypt failed: %v", err)
	}

	decrypted, err := SymDecrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("SymDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text doesn't match original")
	}
}

func TestSymDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ciphertext, _ := SymEncrypt(key1, []byte("secret"))
	_, err := SymDecrypt(key2, ciphertext)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

func TestAsymEncryptDecrypt(t *testing.T) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	plaintext := []byte("secret data for ECIES test")
	ciphertext, err := AsymEncrypt(privKey.PublicKey(), plaintext)
	if err != nil {
		t.Fatalf("AsymEncrypt failed: %v", err)
	}

	decrypted, err := AsymDecrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("AsymDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text doesn't match original")
	}
}

func TestFullEncryptionChain(t *testing.T) {
	// Setup: Access Manager generates KEK/KDK
	am, err := NewAccessManager("/test/read/docs")
	if err != nil {
		t.Fatalf("NewAccessManager failed: %v", err)
	}

	// Consumer generates X25519 key pair
	curve := ecdh.X25519()
	consumerPriv, _ := curve.GenerateKey(rand.Reader)
	consumerKeyName := "/test/consumer/KEY/abc123"

	// Access Manager authorizes consumer
	err = am.AddMember(consumerKeyName, consumerPriv.PublicKey())
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	// Producer encrypts content
	encryptor := NewEncryptor("/test/data", "/test/read/docs", am.KEK())
	plaintext := []byte("This is a secret document that only authorized consumers can read.")

	encContent, encCK, err := encryptor.Encrypt("/test/data/doc1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Consumer gets encrypted KDK from Access Manager
	encKDK, ok := am.GetEncryptedKDK(consumerKeyName)
	if !ok {
		t.Fatal("Consumer should be authorized")
	}

	// Consumer decrypts
	decryptor := NewDecryptor(consumerKeyName, consumerPriv)
	decrypted, err := decryptor.Decrypt(encContent, encCK, encKDK)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestUnauthorizedConsumer(t *testing.T) {
	am, _ := NewAccessManager("/test/read/docs")

	// Unauthorized consumer
	_, ok := am.GetEncryptedKDK("/test/eve/KEY/xyz")
	if ok {
		t.Error("Unauthorized consumer should not get KDK")
	}

	if am.IsAuthorized("/test/eve/KEY/xyz") {
		t.Error("Unauthorized consumer should not be authorized")
	}
}

func TestMultipleConsumers(t *testing.T) {
	am, _ := NewAccessManager("/test/read/docs")

	curve := ecdh.X25519()

	// Alice
	alicePriv, _ := curve.GenerateKey(rand.Reader)
	am.AddMember("/test/alice/KEY/a1", alicePriv.PublicKey())

	// Bob
	bobPriv, _ := curve.GenerateKey(rand.Reader)
	am.AddMember("/test/bob/KEY/b1", bobPriv.PublicKey())

	// Both should be authorized
	if !am.IsAuthorized("/test/alice/KEY/a1") {
		t.Error("Alice should be authorized")
	}
	if !am.IsAuthorized("/test/bob/KEY/b1") {
		t.Error("Bob should be authorized")
	}

	// Encrypt
	encryptor := NewEncryptor("/test/data", "/test/read/docs", am.KEK())
	plaintext := []byte("shared secret")
	encContent, encCK, _ := encryptor.Encrypt("/test/data/doc1", plaintext)

	// Both can decrypt
	for _, tc := range []struct {
		name    string
		keyName string
		privKey *ecdh.PrivateKey
	}{
		{"alice", "/test/alice/KEY/a1", alicePriv},
		{"bob", "/test/bob/KEY/b1", bobPriv},
	} {
		encKDK, ok := am.GetEncryptedKDK(tc.keyName)
		if !ok {
			t.Fatalf("%s should be authorized", tc.name)
		}

		decryptor := NewDecryptor(tc.keyName, tc.privKey)
		decrypted, err := decryptor.Decrypt(encContent, encCK, encKDK)
		if err != nil {
			t.Fatalf("%s decryption failed: %v", tc.name, err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("%s decrypted wrong content", tc.name)
		}
	}

	// Eve cannot decrypt
	evePriv, _ := curve.GenerateKey(rand.Reader)
	_, ok := am.GetEncryptedKDK("/test/eve/KEY/e1")
	if ok {
		t.Error("Eve should not be authorized")
	}
	// Even if Eve somehow got Alice's encrypted KDK, she can't decrypt it
	aliceEncKDK, _ := am.GetEncryptedKDK("/test/alice/KEY/a1")
	_, err := AsymDecrypt(evePriv, aliceEncKDK)
	// This should fail because Eve's private key can't decrypt Alice's KDK
	// (the ECIES ephemeral was for Alice's public key)
	if err == nil {
		t.Error("Eve should not be able to decrypt Alice's KDK")
	}
}

func TestNaming(t *testing.T) {
	kekName := KEKName("/alice/read/docs", []byte{0x01, 0x02})
	if kekName != "/alice/read/docs/E-KEY/0102" {
		t.Errorf("Unexpected KEK name: %s", kekName)
	}

	kdkName := KDKName("/alice/read/docs", []byte{0x01, 0x02})
	if kdkName != "/alice/read/docs/D-KEY/0102" {
		t.Errorf("Unexpected KDK name: %s", kdkName)
	}

	ckName := ContentKeyName("/alice/data", []byte{0xAB, 0xCD})
	if ckName != "/alice/data/CK/abcd" {
		t.Errorf("Unexpected CK name: %s", ckName)
	}

	encName := EncryptedDataName("/alice/data/doc1", "/alice/data/CK/abcd")
	if encName != "/alice/data/doc1/FOR//alice/data/CK/abcd" {
		t.Errorf("Unexpected encrypted data name: %s", encName)
	}

	content, key, err := ParseEncryptedDataName(encName)
	if err != nil {
		t.Fatalf("ParseEncryptedDataName failed: %v", err)
	}
	if content != "/alice/data/doc1" {
		t.Errorf("Unexpected content name: %s", content)
	}
	if key != "/alice/data/CK/abcd" {
		t.Errorf("Unexpected key name: %s", key)
	}
}

func TestKeySerialization(t *testing.T) {
	curve := ecdh.X25519()
	priv, _ := curve.GenerateKey(rand.Reader)

	// Serialize/deserialize public key
	pubBytes := priv.PublicKey().Bytes()
	pub2, err := DeserializePublicKey(pubBytes)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), pub2.Bytes()) {
		t.Error("Public key round-trip failed")
	}

	// Serialize/deserialize private key
	privBytes := priv.Bytes()
	priv2, err := DeserializePrivateKey(privBytes)
	if err != nil {
		t.Fatalf("DeserializePrivateKey failed: %v", err)
	}
	if !bytes.Equal(priv.Bytes(), priv2.Bytes()) {
		t.Error("Private key round-trip failed")
	}
}
