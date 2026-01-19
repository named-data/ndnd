package keychain

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
)

// shared keychain state used by multiple implementations.
type keyChainState struct {
	identities []ndn.KeyChainIdentity
	certNames  []enc.Name
	pubStore   ndn.Store
}

func newKeyChainState(pubStore ndn.Store) *keyChainState {
	return &keyChainState{
		identities: make([]ndn.KeyChainIdentity, 0),
		certNames:  make([]enc.Name, 0),
		pubStore:   pubStore,
	}
}

func isCertName(name enc.Name) bool {
	if len(name) < 4 {
		return false
	}
	if !name.At(-4).IsGeneric("KEY") {
		return false
	}
	if !name.At(-1).IsVersion() {
		return false
	}
	return true
}

func (kc *keyChainState) rebuildKeyCerts() {
	for _, id := range kc.identities {
		idObj := id.(*keyChainIdentity)
		for _, key := range idObj.keyList {
			key := key.(*keyChainKey)
			key.uniqueCerts = nil
			key.latestCertVer = 0
			for _, certName := range kc.certNames {
				if key.KeyName().IsPrefix(certName) {
					key.insertCert(certName)
				}
			}
		}
		idObj.sort()
	}
}

func (kc *keyChainState) Identities() []ndn.KeyChainIdentity {
	return kc.identities
}

func (kc *keyChainState) IdentityByName(name enc.Name) ndn.KeyChainIdentity {
	for _, id := range kc.identities {
		if id.Name().Equal(name) {
			return id
		}
	}
	return nil
}

func (kc *keyChainState) insertKey(signer ndn.Signer) error {
	// Get key name
	keyName := signer.KeyName()
	idName, err := sec.GetIdentityFromKeyName(keyName)
	if err != nil {
		return err
	}

	// Check if signer already exists
	idObj, _ := kc.IdentityByName(idName).(*keyChainIdentity)
	if idObj != nil {
		for _, key := range idObj.Keys() {
			if key.KeyName().Equal(keyName) {
				return nil // not an error
			}
		}
	} else {
		// Create new identity if not exists
		idObj = &keyChainIdentity{name: idName}
		kc.identities = append(kc.identities, idObj)
	}

	// Attach any existing certificates to the signer
	key := &keyChainKey{signer: signer}
	for _, certName := range kc.certNames {
		if keyName.IsPrefix(certName) {
			key.insertCert(certName)
		}
	}

	// Insert signer to identity
	idObj.keyList = append(idObj.keyList, key)
	idObj.sort()

	return nil
}

func (kc *keyChainState) insertCert(wire []byte) error {
	data, _, err := spec.Spec{}.ReadData(enc.NewBufferView(wire))
	if err != nil {
		return err
	}

	contentType, ok := data.ContentType().Get()
	if !ok || contentType != ndn.ContentTypeKey {
		return ndn.ErrInvalidValue{Item: "content type"}
	}

	// /<IdentityName>/KEY/<KeyId>/<IssuerId>/<Version>
	name := data.Name()
	if !isCertName(name) {
		return ndn.ErrInvalidValue{Item: "certificate name"}
	}

	// Check if certificate is valid
	if sec.CertIsExpired(data) {
		return ndn.ErrInvalidValue{Item: "certificate expiry"}
	}

	// Check if certificate already exists
	for _, existing := range kc.certNames {
		if existing.Equal(name) {
			return nil // not an error
		}
	}
	kc.certNames = append(kc.certNames, name)

	// Insert certificate to public store
	if err := kc.pubStore.Put(name, wire); err != nil {
		return err
	}

	// Update identities with the new certificate
	for _, id := range kc.identities {
		id.(*keyChainIdentity).insertCert(name)
	}

	return nil
}

func (kc *keyChainState) deleteKey(keyName enc.Name) error {
	if _, err := sec.GetIdentityFromKeyName(keyName); err != nil {
		return err
	}

	idObj := (*keyChainIdentity)(nil)
	idIdx := -1
	keyIdx := -1
	for i, id := range kc.identities {
		obj := id.(*keyChainIdentity)
		for j, key := range obj.keyList {
			if key.KeyName().Equal(keyName) {
				idObj, idIdx, keyIdx = obj, i, j
				break
			}
		}
		if idObj != nil {
			break
		}
	}
	if idObj == nil {
		return enc.ErrNotFound{Key: keyName.String()}
	}

	// Remove key from identity.
	idObj.keyList = append(idObj.keyList[:keyIdx], idObj.keyList[keyIdx+1:]...)
	if len(idObj.keyList) == 0 {
		kc.identities = append(kc.identities[:idIdx], kc.identities[idIdx+1:]...)
	}

	// Remove certificates associated with this key.
	removedCerts := make([]enc.Name, 0)
	kept := kc.certNames[:0]
	for _, cert := range kc.certNames {
		if keyName.IsPrefix(cert) {
			removedCerts = append(removedCerts, cert)
			continue
		}
		kept = append(kept, cert)
	}
	kc.certNames = kept

	var lastErr error
	for _, cert := range removedCerts {
		if err := kc.pubStore.Remove(cert); err != nil {
			lastErr = err
		}
	}

	kc.rebuildKeyCerts()

	return lastErr
}

func (kc *keyChainState) deleteCert(name enc.Name) error {
	if !isCertName(name) {
		return ndn.ErrInvalidValue{Item: "certificate name"}
	}

	idx := -1
	for i, cert := range kc.certNames {
		if cert.Equal(name) {
			idx = i
			break
		}
	}

	if idx < 0 {
		return enc.ErrNotFound{Key: name.String()}
	}

	if err := kc.pubStore.Remove(name); err != nil {
		return err
	}

	kc.certNames = append(kc.certNames[:idx], kc.certNames[idx+1:]...)
	kc.rebuildKeyCerts()

	return nil
}

func (kc *keyChainState) CertNames() []enc.Name {
	return kc.certNames
}
