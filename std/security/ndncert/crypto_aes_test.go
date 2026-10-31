package ndncert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/named-data/ndnd/std/security/ndncert/tlv"
)

var testAeadKey = [16]byte{1, 2, 3}
var testAeadInfo = []byte("request-id")
var testLocalPrefix = [8]byte{1}
var testPeerPrefix = [8]byte{2}

// (AI GENERATED DESCRIPTION): Construct peer packets independently of AeadEncrypt, so a matching encoder
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

func TestAeadReceiveValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		prefix  [8]byte
		counter uint32
		size    int
	}{
		{"replay", testPeerPrefix, 0, 17},
		{"overlapping blocks", testPeerPrefix, 1, 1},
		{"changed prefix", [8]byte{3}, 2, 1},
		{"local prefix", testLocalPrefix, 2, 1},
		{"wrap", testPeerPrefix, ^uint32(0), 17},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &AeadCounter{sendPrefix: testLocalPrefix}
			if _, err := AeadDecrypt(testAeadKey, referenceAeadMessage(t, testPeerPrefix, 0, 17), testAeadInfo, c); err != nil {
				t.Fatal(err)
			}
			before := *c
			if _, err := AeadDecrypt(testAeadKey, referenceAeadMessage(t, test.prefix, test.counter, test.size), testAeadInfo, c); err == nil {
				t.Fatal("accepted invalid peer IV state")
			}
			if *c != before {
				t.Fatal("invalid packet changed receive state")
			}
			// (AI GENERATED DESCRIPTION): A rejected packet must not prevent the legitimate next packet.
			if _, err := AeadDecrypt(testAeadKey, referenceAeadMessage(t, testPeerPrefix, 2, 1), testAeadInfo, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAeadReceiveAuthentication(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(fmt.Sprint(initialized), func(t *testing.T) {
			c := &AeadCounter{sendPrefix: testLocalPrefix}
			if initialized {
				if _, err := AeadDecrypt(testAeadKey, referenceAeadMessage(t, testPeerPrefix, 0, 1), testAeadInfo, c); err != nil {
					t.Fatal(err)
				}
			}
			before := *c
			m := referenceAeadMessage(t, [8]byte{3}, 100, 1)
			m.AuthTag[0] ^= 1
			if _, err := AeadDecrypt(testAeadKey, m, testAeadInfo, c); err == nil {
				t.Fatal("accepted forged tag")
			}
			if *c != before {
				t.Fatal("unauthenticated packet changed receive state")
			}
			m = referenceAeadMessage(t, testPeerPrefix, 1, 1)
			if _, err := AeadDecrypt(testAeadKey, m, []byte("wrong request"), c); err == nil {
				t.Fatal("accepted wrong request ID")
			}
			if *c != before {
				t.Fatal("wrong AAD changed receive state")
			}
			if _, err := AeadDecrypt(testAeadKey, m, testAeadInfo, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAeadReceiveExhaustion(t *testing.T) {
	c := &AeadCounter{sendPrefix: testLocalPrefix}
	// (AI GENERATED DESCRIPTION): Gaps are permitted, including when earlier messages were lost.
	m := referenceAeadMessage(t, testPeerPrefix, ^uint32(0), 16)
	if _, err := AeadDecrypt(testAeadKey, m, testAeadInfo, c); err != nil {
		t.Fatal(err)
	}
	if c.nextPeerBlock != aeadCounterLimit {
		t.Fatal("receive counter wrapped")
	}
	if _, err := AeadDecrypt(testAeadKey, referenceAeadMessage(t, testPeerPrefix, 0, 1), testAeadInfo, c); err == nil {
		t.Fatal("accepted wrapped counter")
	}
	if _, err := AeadDecrypt(testAeadKey, m, testAeadInfo, nil); err == nil {
		t.Fatal("accepted missing session")
	}
	c = &AeadCounter{sendPrefix: testPeerPrefix}
	if _, err := AeadDecrypt(testAeadKey, m, testAeadInfo, c); err == nil {
		t.Fatal("accepted local prefix on first message")
	}
}

func TestAeadDoesNotModifyPacket(t *testing.T) {
	m := referenceAeadMessage(t, testPeerPrefix, 0, 1)
	packet := bytes.Repeat([]byte{0xaa}, 64)
	copy(packet, m.CipherText)
	m.CipherText = packet[:1]
	before := bytes.Clone(packet)
	if _, err := AeadDecrypt(testAeadKey, m, testAeadInfo, &AeadCounter{sendPrefix: testLocalPrefix}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, before) {
		t.Fatal("decryption overwrote packet backing array")
	}
}

func TestAeadDuplex(t *testing.T) {
	a := &AeadCounter{sendPrefix: testLocalPrefix}
	b := &AeadCounter{sendPrefix: testPeerPrefix}
	for i := 0; i < 3; i++ {
		for _, pair := range [][2]*AeadCounter{{a, b}, {b, a}} {
			m, err := AeadEncrypt(testAeadKey, []byte("challenge"), testAeadInfo, pair[0])
			if err != nil {
				t.Fatal(err)
			}
			got, err := AeadDecrypt(testAeadKey, *m, testAeadInfo, pair[1])
			if err != nil || string(got) != "challenge" {
				t.Fatalf("got %q, %v", got, err)
			}
		}
	}
}

func TestAeadFromTLV(t *testing.T) {
	for _, input := range []*tlv.CipherMsg{
		nil,
		{InitVec: make([]byte, 11), AuthNTag: make([]byte, 16)},
		{InitVec: make([]byte, 13), AuthNTag: make([]byte, 16)},
		{InitVec: make([]byte, 12), AuthNTag: make([]byte, 15)},
		{InitVec: make([]byte, 12), AuthNTag: make([]byte, 17)},
	} {
		if err := new(AeadMessage).FromTLV(input); err == nil {
			t.Fatal("accepted malformed AEAD TLV")
		}
	}
	want := referenceAeadMessage(t, testPeerPrefix, 0, 1)
	var got AeadMessage
	if err := got.FromTLV(want.TLV()); err != nil {
		t.Fatal(err)
	}
	if got.IV != want.IV || got.AuthTag != want.AuthTag || !bytes.Equal(got.CipherText, want.CipherText) {
		t.Fatal("TLV round-trip changed message")
	}
}
