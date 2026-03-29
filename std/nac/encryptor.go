package nac

// EncryptedContent: encrypted content packet
type EncryptedContent struct {
	Name             string // <content-name>/FOR/<ck-name>
	EncryptedPayload []byte // output of SymEncrypt(ck, plaintext)
}

// EncryptedCK: encrypted content key packet
type EncryptedCK struct {
	Name             string // <ck-name>/FOR/<kek-name>
	EncryptedPayload []byte // output of AsymEncrypt(kek, ck.Key)
}

// Encryptor: producer side encryption, takes plaintext+KEK, produces encrypted content + encrypted CK

type Encryptor struct {
	dataPrefix string            // /alice/samples/documents
	credPrefix string            // /alice/read/documents
	kek        *KeyEncryptionKey // fetched from access manager (via NDN Interest)
}

// NewEncryptor: creates encryptor, kek is passed directly for now (fetched via Interest)
func NewEncryptor(dataPrefix, credentialPrefix string, kek *KeyEncryptionKey) *Encryptor {
	return &Encryptor{
		dataPrefix: dataPrefix,
		credPrefix: credentialPrefix,
		kek:        kek,
	}
}

// Encrypt: encrypts content item, generates fresh CK
func (e *Encryptor) Encrypt(contentName string, plaintext []byte) (*EncryptedContent, *EncryptedCK, error) {
	ck, err := NewContentKey()
	if err != nil {
		return nil, nil, err
	}
	// encrypt content
	encPayload, err := SymEncrypt(ck.Key, plaintext)
	if err != nil {
		return nil, nil, err
	}
	// build encrypted content packet
	ckName := ContentKeyName(e.dataPrefix, ck.ID)
	// fmt.Printf("ckName=%s contentName=%s\n", ckName, contentName)
	encContent := &EncryptedContent{
		Name:             EncryptedDataName(contentName, ckName),
		EncryptedPayload: encPayload,
	}

	encCKPayload, err := AsymEncrypt(e.kek.PublicKey, ck.Key)
	if err != nil {
		return nil, nil, err
	}

	// build encrypted CK packet
	kekName := KEKName(e.credPrefix, e.kek.ID)
	encCK := &EncryptedCK{
		Name:             EncryptedDataName(ckName, kekName),
		EncryptedPayload: encCKPayload,
	}

	return encContent, encCK, nil
}
