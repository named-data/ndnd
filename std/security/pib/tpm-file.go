package sqlitepib

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
)

type FileTpm struct {
	path string
}

func (tpm *FileTpm) String() string {
	return fmt.Sprintf("file-tpm (%s)", tpm.path)
}

func (tpm *FileTpm) ToFileName(keyNameBytes []byte) string {
	h := sha256.New()
	h.Write(keyNameBytes)
	return hex.EncodeToString(h.Sum(nil)) + ".privkey"
}

func (tpm *FileTpm) GetSigner(keyName enc.Name, keyLocatorName enc.Name) ndn.Signer {
	keyNameBytes := keyName.Bytes()
	fileName := path.Join(tpm.path, tpm.ToFileName(keyNameBytes))

	text, err := os.ReadFile(fileName)
	if err != nil {
		log.Error(tpm, "Unable to read private key file", "file", fileName, "error", err)
		return nil
	}

	blockLen := base64.StdEncoding.DecodedLen(len(text))
	block := make([]byte, blockLen)
	n, err := base64.StdEncoding.Decode(block, text)
	if err != nil {
		log.Error(tpm, "Unable to base64 decode private key file", "file", fileName, "error", err)
		return nil
	}
	block = block[:n]

	// There are only two formats: PKCS1 encoded RSA, or EC
	eckbits, err := x509.ParseECPrivateKey(block)
	if err == nil {
		// ECC Key
		// TODO: Handle for Interest
		return sec.NewEccSigner(false, false, 0, eckbits, keyLocatorName)
	}

	rsabits, err := x509.ParsePKCS1PrivateKey(block)
	if err == nil {
		// RSA Key
		// TODO: Handle for Interest
		return sec.NewRsaSigner(false, false, 0, rsabits, keyLocatorName)
	}

	log.Error(tpm, "Unrecognized private key format", "file", fileName)
	return nil
}

func (tpm *FileTpm) GenerateKey(keyName enc.Name, keyType string, keySize uint64) enc.Buffer {
	panic("not implemented")
}

func (tpm *FileTpm) KeyExist(keyName enc.Name) bool {
	keyNameBytes := keyName.Bytes()
	fileName := path.Join(tpm.path, tpm.ToFileName(keyNameBytes))
	_, err := os.Stat(fileName)
	return err == nil
}

func (tpm *FileTpm) DeleteKey(keyName enc.Name) {
	panic("not implemented")
}

func NewFileTpm(path string) Tpm {
	return &FileTpm{
		path: path,
	}
}
