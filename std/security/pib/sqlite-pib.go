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

func (pib *SqlitePib) String() string {
	return "sqlite-pib"
}

func (pib *SqlitePib) Tpm() Tpm {
	return pib.tpm
}

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
	data, _, err := spec.Spec{}.ReadData(enc.NewBufferReader(ret.certBits))
	if err != nil || data.Signature() == nil {
		return nil
	}
	ret.keyLocator = data.Signature().KeyName()
	return ret
}

func (pib *SqlitePib) GetSignerForCert(certName enc.Name) ndn.Signer {
	l := len(certName)
	if l < 2 {
		return nil
	}
	return pib.tpm.GetSigner(certName[:l-2], certName)
}

func (iden *SqliteIdent) Name() enc.Name {
	return iden.name
}

func (iden *SqliteIdent) GetKey(keyName enc.Name) Key {
	return iden.pib.GetKey(keyName)
}

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

func (cert *SqliteCert) Name() enc.Name {
	return cert.name
}

func (cert *SqliteCert) KeyLocator() enc.Name {
	return cert.keyLocator
}

func (cert *SqliteCert) Key() Key {
	l := len(cert.name)
	if l < 2 {
		return nil
	}
	return cert.pib.GetKey(cert.name[:l-2])
}

func (cert *SqliteCert) Data() []byte {
	return cert.certBits
}

func (cert *SqliteCert) AsSigner() ndn.Signer {
	return cert.pib.GetSignerForCert(cert.name)
}

func (key *SqliteKey) Name() enc.Name {
	return key.name
}

func (key *SqliteKey) Identity() Identity {
	l := len(key.name)
	if l < 2 {
		return nil
	}
	return key.pib.GetIdentity(key.name[:l-2])
}

func (key *SqliteKey) KeyBits() []byte {
	return key.keyBits
}

func (key *SqliteKey) SelfSignedCert() Cert {
	return key.FindCert(func(cert Cert) bool {
		l := len(cert.Name())
		selfComp := enc.NewStringComponent(enc.TypeGenericNameComponent, "self")
		return l > 2 && cert.Name()[l-2].Equal(selfComp)
	})
}

func (key *SqliteKey) GetCert(certName enc.Name) Cert {
	return key.pib.GetCert(certName)
}

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
		data, _, err := spec.Spec{}.ReadData(enc.NewBufferReader(ret.certBits))
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
