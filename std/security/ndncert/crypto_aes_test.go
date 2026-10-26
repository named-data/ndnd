package ndncert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

var testAeadKey = [16]byte{1, 2, 3}
var testAeadInfo = []byte("request-id")
var testLocalPrefix = [8]byte{1}
var testPeerPrefix = [8]byte{2}

// Construct peer packets independently of AeadEncrypt, so a matching encoder
// and decoder bug cannot make the receive-side tests pass.
func referenceAeadMessage(t *testing.T, prefix [8]byte, counter uint32, size int) AeadMessage {
	t.Helper()
	block, err := aes.NewCipher(testAeadKey[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	m := AeadMessage{}
	copy(m.IV[:], prefix[:])
	binary.BigEndian.PutUint32(m.IV[8:], counter)
	sealed := gcm.Seal(nil, m.IV[:], bytes.Repeat([]byte{42}, size), testAeadInfo)
	m.CipherText = sealed[:size]
	copy(m.AuthTag[:], sealed[size:])
	return m
}

func TestAeadSendCounter(t *testing.T) {
	counter := &AeadCounter{sendPrefix: testLocalPrefix}
	var next uint64
	for _, size := range []int{1, 15, 16, 17, 32, 33} {
		m, err := AeadEncrypt(testAeadKey, bytes.Repeat([]byte{42}, size), testAeadInfo, counter)
		if err != nil {
			t.Fatal(err)
		}
		want := referenceAeadMessage(t, testLocalPrefix, uint32(next), size)
		if m.IV != want.IV || m.AuthTag != want.AuthTag || !bytes.Equal(m.CipherText, want.CipherText) {
			t.Fatalf("size %d: encryption differs from reference at counter %d", size, next)
		}
		next += uint64((size + 15) / 16)
		if counter.nextSendBlock != next {
			t.Fatalf("size %d: next counter = %d, want %d", size, counter.nextSendBlock, next)
		}
	}
	counter.nextSendBlock = 0x01020304
	m, err := AeadEncrypt(testAeadKey, []byte{42}, testAeadInfo, counter)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.IV[8:], []byte{1, 2, 3, 4}) {
		t.Fatalf("counter is not big-endian: %x", m.IV)
	}
}

func TestAeadBlockArithmetic(t *testing.T) {
	for _, size := range []int{1, 15, 16, 17, (1 << 24) + 1, int(^uint(0) >> 1)} {
		want := uint64(size / 16)
		if size%16 != 0 {
			want++
		}
		got, err := aeadBlocks(size)
		if want > aeadCounterLimit-2 {
			if err == nil {
				t.Fatalf("size %d: accepted excessive GCM length", size)
			}
		} else if err != nil || got != want {
			t.Fatalf("size %d: got %d, %v; want %d", size, got, err, want)
		}
	}
	for _, size := range []int{0, -1} {
		if _, err := aeadBlocks(size); err == nil {
			t.Fatalf("accepted length %d", size)
		}
	}
}

func TestAeadSendExhaustion(t *testing.T) {
	c := &AeadCounter{sendPrefix: testLocalPrefix, nextSendBlock: aeadCounterLimit - 1}
	if _, err := AeadEncrypt(testAeadKey, make([]byte, 17), testAeadInfo, c); err == nil {
		t.Fatal("accepted wrapping counter")
	}
	if c.nextSendBlock != aeadCounterLimit-1 {
		t.Fatal("failed send consumed counter")
	}
	m, err := AeadEncrypt(testAeadKey, []byte{1}, testAeadInfo, c)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(m.IV[8:]) != ^uint32(0) || c.nextSendBlock != aeadCounterLimit {
		t.Fatal("last counter was not used safely")
	}
	if _, err := AeadEncrypt(testAeadKey, []byte{1}, testAeadInfo, c); err == nil {
		t.Fatal("accepted exhausted counter")
	}
	if _, err := AeadEncrypt(testAeadKey, nil, testAeadInfo, c); err == nil {
		t.Fatal("accepted empty plaintext")
	}
	if _, err := AeadEncrypt(testAeadKey, []byte{1}, testAeadInfo, nil); err == nil {
		t.Fatal("accepted missing session")
	}
}
