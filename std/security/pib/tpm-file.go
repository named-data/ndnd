package sqlitepib

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
)

type FileTpm struct {
	path string
}

// (AI GENERATED DESCRIPTION): Returns a human‑readable string describing the FileTpm, formatted as “file‑tpm (<path>)”.
func (tpm *FileTpm) String() string {
	return fmt.Sprintf("file-tpm (%s)", tpm.path)
}

// (AI GENERATED DESCRIPTION): Generates a deterministic filename for a private key by hashing the supplied key name bytes with SHA‑256 and appending the “.privkey” extension.
func (tpm *FileTpm) ToFileName(keyNameBytes []byte) string {
	h := sha256.New()
	h.Write(keyNameBytes)
	return hex.EncodeToString(h.Sum(nil)) + ".privkey"
}

// (AI GENERATED DESCRIPTION): Retrieves a signer for a given key name by reading, base64‑decoding, and parsing the private key file stored on disk (returning an RSA or EC signer if recognized).
func (tpm *FileTpm) GetSigner(keyName enc.Name, keyLocatorName enc.Name) ndn.Signer {
	keyNameBytes := keyName.Bytes()
	fileName := path.Join(tpm.path, tpm.ToFileName(keyNameBytes))

	text, err := os.ReadFile(fileName)
	if err != nil {
		log.Error(tpm, "Unable to read private key file", "file", fileName, "err", err)
		return nil
	}

	blockLen := base64.StdEncoding.DecodedLen(len(text))
	block := make([]byte, blockLen)
	n, err := base64.StdEncoding.Decode(block, text)
	if err != nil {
		log.Error(tpm, "Unable to base64 decode private key file", "file", fileName, "err", err)
		return nil
	}
	block = block[:n]

	// There are only two formats: PKCS1 encoded RSA, or EC
	// eckbits, err := x509.ParseECPrivateKey(block)
	// if err == nil {
	// 	// ECC Key
	// 	// TODO: Handle for Interest
	// 	return sec.NewEccSigner(false, false, 0, eckbits, keyLocatorName)
	// }

	// rsabits, err := x509.ParsePKCS1PrivateKey(block)
	// if err == nil {
	// 	// RSA Key
	// 	// TODO: Handle for Interest
	// 	return sec.NewRsaSigner(false, false, 0, rsabits, keyLocatorName)
	// }

	log.Error(tpm, "Unrecognized private key format", "file", fileName)
	return nil
}

// (AI GENERATED DESCRIPTION): Generates a new cryptographic key of the given type and size, stores it in the file‑based TPM under the specified name, and returns the key’s encoded representation as an `enc.Buffer`.
func (tpm *FileTpm) GenerateKey(keyName enc.Name, keyType string, keySize uint64) enc.Buffer {
	panic("not implemented")
}

// (AI GENERATED DESCRIPTION): Checks whether a key with the specified name exists in the FileTpm’s storage by verifying the presence of the corresponding file.
func (tpm *FileTpm) KeyExist(keyName enc.Name) bool {
	keyNameBytes := keyName.Bytes()
	fileName := path.Join(tpm.path, tpm.ToFileName(keyNameBytes))
	_, err := os.Stat(fileName)
	return err == nil
}

// (AI GENERATED DESCRIPTION): Deletes the key identified by `keyName` from the file‑based TPM, removing its stored key material and associated metadata.
func (tpm *FileTpm) DeleteKey(keyName enc.Name) {
	panic("not implemented")
}

// (AI GENERATED DESCRIPTION): Creates a new FileTpm instance initialized with the specified file path.
func NewFileTpm(path string) Tpm {
	return &FileTpm{
		path: path,
	}
}
