package ndncert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/named-data/ndnd/std/security/ndncert/tlv"
)

const AeadSizeNonce = 12
const AeadSizeTag = 16
const AeadSizeRand = 8

type AeadMessage struct {
	IV         [AeadSizeNonce]byte
	AuthTag    [AeadSizeTag]byte
	CipherText []byte
}

// (AI GENERATED DESCRIPTION): Creates a tlv.CipherMsg containing the AEAD message’s IV, authentication tag, and ciphertext.
func (m *AeadMessage) TLV() *tlv.CipherMsg {
	return &tlv.CipherMsg{
		InitVec:  m.IV[:],
		AuthNTag: m.AuthTag[:],
		Payload:  m.CipherText,
	}
}

// (AI GENERATED DESCRIPTION): Populates an AeadMessage's IV, AuthTag, and CipherText fields from a provided tlv.CipherMsg.
func (m *AeadMessage) FromTLV(t *tlv.CipherMsg) {
	m.IV = [AeadSizeNonce]byte(t.InitVec)
	m.AuthTag = [AeadSizeTag]byte(t.AuthNTag)
	m.CipherText = t.Payload
}

// AeadCounter holds the send IV state of one NDNCERT session. It must not be
// reused with a new session key or shared between concurrent operations.
type AeadCounter struct {
	// uint64 represents the exhausted state (2^32) without wrapping to zero.
	nextSendBlock uint64
	sendPrefix    [AeadSizeRand]byte
}

const aeadCounterLimit = uint64(1) << 32

// Empty CHALLENGE plaintext is invalid and would otherwise reuse an IV because
// it consumes zero blocks. Integer division avoids floating-point rounding and
// adding 15 to a potentially large int.
func aeadBlocks(length int) (uint64, error) {
	if length <= 0 {
		return 0, fmt.Errorf("AEAD plaintext must not be empty")
	}
	blocks := uint64(length / aes.BlockSize)
	if length%aes.BlockSize != 0 {
		blocks++
	}
	// GCM itself limits a message to 2^32-2 blocks.
	if blocks > aeadCounterLimit-2 {
		return 0, fmt.Errorf("AEAD message exceeds GCM block limit")
	}
	return blocks, nil
}

// (AI GENERATED DESCRIPTION): Creates a new AeadCounter initialized with a zero block counter and a freshly generated random byte sequence.
func NewAeadCounter() *AeadCounter {
	randomBytes := make([]byte, AeadSizeRand)
	if _, randReadErr := io.ReadFull(rand.Reader, randomBytes); randReadErr != nil {
		panic(randReadErr.Error())
	}
	return &AeadCounter{
		sendPrefix: [AeadSizeRand]byte(randomBytes),
	}
}

// (AI GENERATED DESCRIPTION): Encrypts the given plaintext with AES‑GCM using the supplied key and context info, deriving an IV from the counter, and returns an `AeadMessage` containing the IV, ciphertext, and authentication tag.
func AeadEncrypt(
	key [AeadSizeTag]byte,
	plaintext []byte,
	info []byte,
	counter *AeadCounter,
) (*AeadMessage, error) {
	if counter == nil {
		return nil, fmt.Errorf("AEAD session counter is required")
	}
	blocks, err := aeadBlocks(len(plaintext))
	if err != nil {
		return nil, err
	}
	if counter.nextSendBlock >= aeadCounterLimit || blocks > aeadCounterLimit-counter.nextSendBlock {
		return nil, fmt.Errorf("AEAD send counter exhausted")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// NDNCERT v0.3: use the current counter, in network byte order, then
	// advance by the number of plaintext AES blocks after encryption.
	var iv [AeadSizeNonce]byte
	copy(iv[:], counter.sendPrefix[:])
	binary.BigEndian.PutUint32(iv[AeadSizeRand:], uint32(counter.nextSendBlock))

	// Encrypt and seal
	output := aesgcm.Seal(nil, iv[:], plaintext, info)
	counter.nextSendBlock += blocks

	return &AeadMessage{
		IV:         iv,
		AuthTag:    ([AeadSizeTag]byte)(output[len(plaintext):]),
		CipherText: output[:len(plaintext)],
	}, nil
}

// (AI GENERATED DESCRIPTION): Decrypts an AEAD‑protected message using AES‑GCM with the given key and additional authenticated data.
func AeadDecrypt(
	key [AeadSizeTag]byte,
	message AeadMessage,
	info []byte,
) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	nonce := message.IV[:]
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := append(message.CipherText, message.AuthTag[:]...)

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, info[:])
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
