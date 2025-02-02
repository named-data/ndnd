package security

import (
	"errors"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
)

// DecodeFile decodes all signers and certs from the given content.
// The input can either be TLV or PEM encoded.
// If PEM encoded, the input may have more than one signers and/or certs.
// May return empty slices for signers and certs if no valid entries.
func DecodeFile(content []byte) (signers []ndn.Signer, certs [][]byte, err error) {
	if len(content) == 0 {
		err = errors.New("empty keychain entry")
		return
	}

	var wires [][]byte
	if content[0] == 0x06 { // raw data
		wires = append(wires, content)
	} else { // try text
		wires = PemDecode(content)
	}
	if len(wires) == 0 {
		err = errors.New("no valid keychain entry found")
		return
	}

	for _, wire := range wires {
		data, _, err := spec.Spec{}.ReadData(enc.NewFastBufReader(wire))
		if err != nil {
			log.Warn(nil, "Failed to read keychain entry", "err", err)
			continue
		}

		if data.ContentType() == nil {
			log.Warn(nil, "No content type found", "name", data.Name())
			continue
		}

		switch *data.ContentType() {
		case ndn.ContentTypeKey: // cert
			certs = append(certs, wire)
		case ndn.ContentTypeSigKey: // key
			key, err := sig.UnmarshalSecret(data)
			if err != nil || key == nil {
				log.Warn(nil, "Failed to decode key", "name", data.Name(), "err", err)
				continue
			}
			signers = append(signers, key)
		default:
			log.Warn(nil, "Unknown content type", "name", data.Name(), "type", *data.ContentType())
		}
	}

	err = nil
	return
}
