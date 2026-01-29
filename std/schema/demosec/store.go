// demosec gives a proof-of-concept demo of how security will be implemented in NTSchema
package demosec

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

type DemoHmacKey struct {
	KeyName  enc.Name // In this demo KeyName = CertName
	KeyBits  enc.Buffer
	CertData enc.Buffer
}

type DemoHmacKeyStore struct {
	Keys []DemoHmacKey
}

// AddTrustAnchor simulates the addition of a trust anchor (self-signed certificate)
func (store *DemoHmacKeyStore) AddTrustAnchor(cert enc.Buffer) error {
	spec := spec_2022.Spec{}
	data, sigCovered, err := spec.ReadData(enc.NewBufferView(cert))
	if err != nil {
		return fmt.Errorf("unable to parse certificate: %+v", err)
	}
	keyBits := data.Content().Join()
	if !sig.ValidateHmac(sigCovered, data.Signature(), keyBits) {
		return fmt.Errorf("the certificate is not properly self-signed")
	}
	return store.SaveKey(data.Name(), keyBits, cert)
}

// EnrollKey simulates the creation of a certificate
func (store *DemoHmacKeyStore) EnrollKey(keyName enc.Name, keyBits enc.Buffer, signKeyName enc.Name) error {
	signKey := store.GetKey(signKeyName)
	if signKey == nil {
		return fmt.Errorf("cannot find signing key: %s", signKeyName.String())
	}
	signer := sig.NewHmacSigner(signKey.KeyBits)
	spec := spec_2022.Spec{}
	cert, err := spec.MakeData(keyName, &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeKey),
		Freshness:   optional.Some(3600 * time.Second),
	}, enc.Wire{keyBits}, signer)
	if err != nil {
		return fmt.Errorf("unable to make certificate: %+v", err)
	}
	return store.SaveKey(keyName, keyBits, cert.Wire.Join())
}

// GetKey returns the key & cert of a specific key name
func (store *DemoHmacKeyStore) GetKey(keyName enc.Name) *DemoHmacKey {
	idx := -1
	for i, key := range store.Keys {
		if keyName.Equal(key.KeyName) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil
	}
	return &store.Keys[idx]
}

// SaveKey simulates storing a fetched certificate
func (store *DemoHmacKeyStore) SaveKey(name enc.Name, keyBits enc.Buffer, cert enc.Buffer) error {
	store.Keys = append(store.Keys, DemoHmacKey{
		KeyName:  name,
		KeyBits:  keyBits,
		CertData: cert,
	})
	return nil
}

// (AI GENERATED DESCRIPTION): Creates a new DemoHmacKeyStore instance with an empty slice of DemoHmacKey entries.
func NewDemoHmacKeyStore() *DemoHmacKeyStore {
	return &DemoHmacKeyStore{
		Keys: make([]DemoHmacKey, 0),
	}
}
