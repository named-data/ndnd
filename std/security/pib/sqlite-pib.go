package sqlitepib

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
)

type SqliteCert struct {
	pib        *SqlitePib
	rowId      uint
	name       enc.Name
	certBits   []byte
	isDefault  bool
	keyLocator enc.Name
}

type SqliteKey struct {
	pib       *SqlitePib
	rowId     uint
	name      enc.Name
	keyBits   []byte
	isDefault bool
}

type SqliteIdent struct {
	pib       *SqlitePib
	rowId     uint
	name      enc.Name
	isDefault bool
}

type SqlitePib struct {
	db  *sql.DB
	tpm Tpm
}

// (AI GENERATED DESCRIPTION): Returns a string identifier for the SqlitePib implementation, i.e., `"sqlite-pib"`.
func (pib *SqlitePib) String() string {
	return "sqlite-pib"
}

// (AI GENERATED DESCRIPTION): Returns the TPM instance used by the SqlitePib.
func (pib *SqlitePib) Tpm() Tpm {
	return pib.tpm
}

// (AI GENERATED DESCRIPTION): Retrieves an identity from the PIB database by its name, returning a `SqliteIdent` instance if a matching record exists, otherwise nil.
func (pib *SqlitePib) GetIdentity(name enc.Name) Identity {
	nameWire := name.Bytes()
	rows, err := pib.db.Query("SELECT id, is_default FROM identities WHERE identity=?", nameWire)
	if err != nil {
		return nil
	}
	defer rows.Close()
	if !rows.Next() {
		return nil
	}
	ret := &SqliteIdent{
		pib:  pib,
		name: name,
	}
	err = rows.Scan(&ret.rowId, &ret.isDefault)
	if err != nil {
		return nil
	}
	return ret
}

// (AI GENERATED DESCRIPTION): Retrieves a key from the SQLite PIB by name, returning a Key instance or nil if the key is missing or an error occurs.
func (pib *SqlitePib) GetKey(keyName enc.Name) Key {
	nameWire := keyName.Bytes()
	rows, err := pib.db.Query("SELECT id, key_bits, is_default FROM keys WHERE key_name=?", nameWire)
	if err != nil {
		return nil
	}
	defer rows.Close()
	if !rows.Next() {
		return nil
	}
	ret := &SqliteKey{
		pib:  pib,
		name: keyName,
	}
	err = rows.Scan(&ret.rowId, &ret.keyBits, &ret.isDefault)
	if err != nil {
		return nil
	}
	return ret
}

// (AI GENERATED DESCRIPTION): Retrieves the certificate with the given name from the SQLite PIB database, parses its stored data to extract the certificate and signer key, and returns a Cert object populated with this information (or nil if not found or invalid).
func (pib *SqlitePib) GetCert(certName enc.Name) Cert {
	nameWire := certName.Bytes()
	rows, err := pib.db.Query(
		"SELECT id, certificate_data, is_default FROM certificates WHERE certificate_name=?",
		nameWire,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	if !rows.Next() {
		return nil
	}
	ret := &SqliteCert{
		pib:  pib,
		name: certName,
	}
	err = rows.Scan(&ret.rowId, &ret.certBits, &ret.isDefault)
	if err != nil {
		return nil
	}
	// Parse the certificate and get the signer
	data, _, err := spec.Spec{}.ReadData(enc.NewBufferView(ret.certBits))
	if err != nil || data.Signature() == nil {
		return nil
	}
	ret.keyLocator = data.Signature().KeyName()
	return ret
}

// (AI GENERATED DESCRIPTION): Retrieves a Signer for the given certificate name from the TPM, returning nil if the name has fewer than two components.
func (pib *SqlitePib) GetSignerForCert(certName enc.Name) ndn.Signer {
	l := len(certName)
	if l < 2 {
		return nil
	}
	return pib.tpm.GetSigner(certName[:l-2], certName)
}

// (AI GENERATED DESCRIPTION): Returns the name stored in the SqliteIdent instance.
func (iden *SqliteIdent) Name() enc.Name {
	return iden.name
}

// (AI GENERATED DESCRIPTION): Retrieves the Key object identified by `keyName` from the SqliteIdent’s persistent identity base (PIB).
func (iden *SqliteIdent) GetKey(keyName enc.Name) Key {
	return iden.pib.GetKey(keyName)
}

// (AI GENERATED DESCRIPTION): Finds and returns the first certificate belonging to this identity that satisfies a given condition, searching all of its keys and delegating to each key’s FindCert, or nil if no match is found.
func (iden *SqliteIdent) FindCert(check func(Cert) bool) Cert {
	rows, err := iden.pib.db.Query(
		"SELECT id, key_name, key_bits, is_default FROM keys WHERE identity_id=?",
		iden.rowId,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		ret := &SqliteKey{
			pib: iden.pib,
		}
		var keyNameWire []byte
		err = rows.Scan(&ret.rowId, &keyNameWire, &ret.keyBits, &ret.isDefault)
		if err != nil {
			continue
		}
		ret.name, err = enc.NameFromBytes(keyNameWire)
		if err != nil {
			continue
		}
		cert := ret.FindCert(check)
		if cert != nil {
			return cert
		}
	}
	return nil

}

// (AI GENERATED DESCRIPTION): Returns the Name of the certificate stored in this SqliteCert.
func (cert *SqliteCert) Name() enc.Name {
	return cert.name
}

// (AI GENERATED DESCRIPTION): Returns the key‑locator name associated with this certificate.
func (cert *SqliteCert) KeyLocator() enc.Name {
	return cert.keyLocator
}

// (AI GENERATED DESCRIPTION): Retrieves the Key associated with this certificate by dropping the last two components of its name and looking up the resulting key name in the PIB, returning nil if the name is too short.
func (cert *SqliteCert) Key() Key {
	l := len(cert.name)
	if l < 2 {
		return nil
	}
	return cert.pib.GetKey(cert.name[:l-2])
}

// (AI GENERATED DESCRIPTION): Returns the raw certificate bits stored in the SqliteCert.
func (cert *SqliteCert) Data() []byte {
	return cert.certBits
}

// (AI GENERATED DESCRIPTION): Returns an ndn.Signer that signs packets using the private key associated with this certificate.
func (cert *SqliteCert) AsSigner() ndn.Signer {
	return cert.pib.GetSignerForCert(cert.name)
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the name associated with this SqliteKey instance.
func (key *SqliteKey) Name() enc.Name {
	return key.name
}

// (AI GENERATED DESCRIPTION): Retrieves the owning Identity for the key by removing its two‑byte key‑ID suffix from the key’s name and looking up that identity in the PIB; returns nil if the key name is too short.
func (key *SqliteKey) Identity() Identity {
	l := len(key.name)
	if l < 2 {
		return nil
	}
	return key.pib.GetIdentity(key.name[:l-2])
}

// (AI GENERATED DESCRIPTION): Returns the raw key bits of the SqliteKey as a byte slice.
func (key *SqliteKey) KeyBits() []byte {
	return key.keyBits
}

// (AI GENERATED DESCRIPTION): Retrieves the first certificate stored under the key whose name contains the component “self” as the second‑to‑last component, indicating it is a self‑signed cert.
func (key *SqliteKey) SelfSignedCert() Cert {
	return key.FindCert(func(cert Cert) bool {
		l := len(cert.Name())
		selfComp := enc.NewGenericComponent("self")
		return l > 2 && cert.Name()[l-2].Equal(selfComp)
	})
}

// (AI GENERATED DESCRIPTION): Retrieves and returns the certificate identified by the given name from the underlying persistent identity base (PIB).
func (key *SqliteKey) GetCert(certName enc.Name) Cert {
	return key.pib.GetCert(certName)
}

// (AI GENERATED DESCRIPTION): FindCert returns the first certificate linked to the key that satisfies the supplied predicate, or nil if no matching certificate exists.
func (key *SqliteKey) FindCert(check func(Cert) bool) Cert {
	rows, err := key.pib.db.Query(
		"SELECT id, certificate_name, certificate_data, is_default FROM certificates WHERE key_id=?",
		key.rowId,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		ret := &SqliteCert{
			pib: key.pib,
		}
		var certNameWire []byte
		err = rows.Scan(&ret.rowId, &certNameWire, &ret.certBits, &ret.isDefault)
		if err != nil {
			continue
		}
		ret.name, err = enc.NameFromBytes(certNameWire)
		if err != nil {
			continue
		}
		// Parse the certificate and get the signer
		data, _, err := spec.Spec{}.ReadData(enc.NewBufferView(ret.certBits))
		if err != nil || data.Signature() == nil {
			continue
		}
		ret.keyLocator = data.Signature().KeyName()
		if check(ret) {
			return ret
		}
	}
	return nil
}

// (AI GENERATED DESCRIPTION): Initializes a new SqlitePib instance by opening the specified SQLite database and associating it with the provided TPM.
func NewSqlitePib(path string, tpm Tpm) *SqlitePib {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		log.Error(nil, "Unable to connect to sqlite PIB", "err", err)
		return nil
	}
	return &SqlitePib{
		db:  db,
		tpm: tpm,
	}
}
