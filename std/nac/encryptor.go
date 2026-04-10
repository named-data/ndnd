package nac

type EncryptedContent struct {
	CKName           string // CK name for discovery (will be embedded in TLV later)
	EncryptedPayload []byte // SymEncrypt(ck, plaintext)
}

type EncryptedCK struct {
	Name             string // <data-prefix>/CK/<ck-id>/ENCRYPTED-BY/<kek-name>
	EncryptedPayload []byte // AsymEncrypt(kek, ck.Key)
}

// Encryptor: producer-side encryption using NAC key hierarchy.
type Encryptor struct {
	dataPrefix   string
	accessPrefix string
	dataset      string
	kek          *KeyEncryptionKey
}

func NewEncryptor(dataPrefix, accessPrefix, dataset string, kek *KeyEncryptionKey) *Encryptor {
	return &Encryptor{
		dataPrefix:   dataPrefix,
		accessPrefix: accessPrefix,
		dataset:      dataset,
		kek:          kek,
	}
}

// Encrypt encrypts content, generating a fresh CK per invocation.
func (e *Encryptor) Encrypt(contentName string, plaintext []byte) (*EncryptedContent, *EncryptedCK, error) {
	ck, err := NewContentKey()
	if err != nil {
		return nil, nil, err
	}

	encPayload, err := SymEncrypt(ck.Key, plaintext)
	if err != nil {
		return nil, nil, err
	}

	ckName := ContentKeyName(e.dataPrefix, ck.ID)
	encContent := &EncryptedContent{
		CKName:           ckName,
		EncryptedPayload: encPayload,
	}

	encCKPayload, err := AsymEncrypt(e.kek.PublicKey, ck.Key)
	if err != nil {
		return nil, nil, err
	}

	kekName := KEKName(e.accessPrefix, e.dataset, e.kek.ID)
	encCK := &EncryptedCK{
		Name:             CKEncryptedName(e.dataPrefix, ck.ID, kekName),
		EncryptedPayload: encCKPayload,
	}

	return encContent, encCK, nil
}
