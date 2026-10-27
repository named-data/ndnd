package nfdc

import (
	"fmt"
	"os"

	dvconfig "github.com/named-data/ndnd/dv/config"
	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/trust_schema"
)

func (t *Tool) configureStatusTrust() error {
	t.statusTrust = nil
	if len(t.statusTrustAnchors) == 0 {
		if t.statusTrustSchemaPath != "" {
			return fmt.Errorf("--trust-schema requires at least one --trust-anchor")
		}
		return nil
	}
	kc := keychain.NewKeyChainMem(storage.NewMemoryStore())
	var anchors []enc.Name
	for _, path := range t.statusTrustAnchors {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read DV trust anchor %s: %w", path, err)
		}
		_, certs, err := sec.DecodeFile(content)
		if err != nil {
			return fmt.Errorf("decode DV trust anchor %s: %w", path, err)
		}
		if len(certs) == 0 {
			return fmt.Errorf("DV trust anchor %s must contain an NDN certificate", path)
		}
		for _, wire := range certs {
			if err := kc.InsertCert(wire); err != nil {
				return fmt.Errorf("load DV trust anchor %s: %w", path, err)
			}
			cert, _, err := (spec.Spec{}).ReadData(enc.NewBufferView(wire))
			if err != nil {
				return fmt.Errorf("parse DV trust anchor %s: %w", path, err)
			}
			anchors = append(anchors, cert.Name())
		}
	}
	schemaBytes := dvconfig.SchemaBytes
	if t.statusTrustSchemaPath != "" {
		var err error
		schemaBytes, err = os.ReadFile(t.statusTrustSchemaPath)
		if err != nil {
			return fmt.Errorf("read DV status trust schema %s: %w", t.statusTrustSchemaPath, err)
		}
	}
	schema, err := trust_schema.NewLvsSchema(schemaBytes)
	if err != nil {
		return fmt.Errorf("load DV status trust schema: %w", err)
	}
	trust, err := sec.NewTrustConfig(kc, schema, anchors)
	if err != nil {
		return fmt.Errorf("configure DV status validation: %w", err)
	}
	trust.UseDataNameFwHint = true
	t.statusTrust = trust
	return nil
}
