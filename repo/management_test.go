package repo

import (
	"errors"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/stretchr/testify/require"
)

// Commands and certificate-store callbacks run synchronously in these tests.
type managementEngine struct {
	ndn.Engine
	handler ndn.InterestHandler
}

func (e *managementEngine) AttachHandler(_ enc.Name, handler ndn.InterestHandler) error {
	e.handler = handler
	return nil
}

func (e *managementEngine) Spec() ndn.Spec   { return spec.Spec{} }
func (e *managementEngine) Timer() ndn.Timer { return basic.NewTimer() }
func (e *managementEngine) Post(f func())    { f() }
func (e *managementEngine) Express(_ *ndn.EncodedInterest, _ ndn.ExpressCallbackFunc) error {
	return errors.New("certificate unavailable in test store")
}

func TestManagementCommandValidation(t *testing.T) {
	for _, scenario := range []string{"authorized", "wrong-user", "wrong-name", "tampered", "untrusted-root", "expired", "no-response-key"} {
		t.Run(scenario, func(t *testing.T) {
			store := storage.NewMemoryStore()
			kc := keychain.NewKeyChainMem(store)
			before, after := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
			rootKey, err := signer.KeygenEd25519(sec.MakeKeyName(managementName(t, "/ndnd")))
			require.NoError(t, err)
			rootWire, err := sec.SelfSign(sec.SignCertArgs{Signer: rootKey, NotBefore: before, NotAfter: after})
			require.NoError(t, err)
			root, _, err := (spec.Spec{}).ReadData(enc.NewWireView(rootWire))
			require.NoError(t, err)
			require.NoError(t, kc.InsertCert(rootWire.Join()))
			issuer := rootKey
			if scenario == "untrusted-root" {
				issuer, err = signer.KeygenEd25519(sec.MakeKeyName(managementName(t, "/ndnd")))
				require.NoError(t, err)
				wire, err := sec.SelfSign(sec.SignCertArgs{Signer: issuer, NotBefore: before, NotAfter: after})
				require.NoError(t, err)
				require.NoError(t, kc.InsertCert(wire.Join()))
			}
			user := "/ndnd/users/alice"
			if scenario == "wrong-user" {
				user = "/ndnd/users/bob"
			}
			userKey, err := signer.KeygenEd25519(sec.MakeKeyName(managementName(t, user)))
			require.NoError(t, err)
			secret, err := signer.MarshalSecretToData(userKey)
			require.NoError(t, err)
			certAfter := after
			if scenario == "expired" {
				certAfter = time.Now().Add(-time.Minute)
			}
			userCert, err := sec.SignCert(sec.SignCertArgs{Signer: issuer, Data: secret,
				IssuerId: enc.NewGenericComponent("root"), NotBefore: before, NotAfter: certAfter})
			require.NoError(t, err)
			cert, _, err := (spec.Spec{}).ReadData(enc.NewWireView(userCert))
			require.NoError(t, err)
			// Include expired certificates in the fetch store to exercise validation.
			require.NoError(t, store.Put(cert.Name(), userCert.Join()))

			repoKey, err := signer.KeygenEd25519(sec.MakeKeyName(managementName(t, "/ndnd/site/repo")))
			require.NoError(t, err)
			secret, err = signer.MarshalSecretToData(repoKey)
			require.NoError(t, err)
			repoCertWire, err := sec.SignCert(sec.SignCertArgs{Signer: rootKey, Data: secret,
				IssuerId: enc.NewGenericComponent("root"), NotBefore: before, NotAfter: after})
			require.NoError(t, err)
			if scenario != "no-response-key" {
				require.NoError(t, kc.InsertKey(repoKey))
				require.NoError(t, kc.InsertCert(repoCertWire.Join()))
			}
			schema, err := (&Config{TrustSchema: "testdata/management.tlv"}).managementSchema()
			require.NoError(t, err)
			trust, err := sec.NewTrustConfig(kc, schema, []enc.Name{root.Name()})
			require.NoError(t, err)
			engine := &managementEngine{}
			client := object.NewClient(engine, store, trust)
			dispatched := false
			var replyErr error
			dest := managementName(t, "/ndnd/site/repo/32=cmd")
			require.NoError(t, client.AttachCommandHandler(dest, func(_ enc.Name, _ enc.Wire, reply func(enc.Wire) error) {
				dispatched = true
				replyErr = reply(enc.Wire{[]byte("accepted")})
			}))
			commandName := managementName(t, "/ndnd/users/alice/32=repo")
			if scenario == "wrong-name" {
				commandName = managementName(t, "/ndnd/users/alice/unauthorized")
			}
			command, err := (spec.Spec{}).MakeData(commandName, &ndn.DataConfig{}, enc.Wire{[]byte("command")}, userKey)
			require.NoError(t, err)
			wire := command.Wire.Join()
			if scenario == "tampered" {
				wire[len(wire)-1] ^= 1
			}
			interestWire, err := (spec.Spec{}).MakeInterest(dest, &ndn.InterestConfig{}, enc.Wire{wire}, nil)
			require.NoError(t, err)
			interest, _, err := (spec.Spec{}).ReadInterest(enc.NewWireView(interestWire.Wire))
			require.NoError(t, err)
			var response enc.Wire
			engine.handler(ndn.InterestHandlerArgs{Interest: interest, Reply: func(wire enc.Wire) error {
				response = wire
				return nil
			}})
			allowed := scenario == "authorized" || scenario == "no-response-key"
			require.Equal(t, allowed, dispatched)
			if scenario == "no-response-key" {
				require.ErrorContains(t, replyErr, "no signer found")
			}
			if scenario != "authorized" {
				require.Empty(t, response)
				return
			}
			require.NoError(t, replyErr)
			data, covered, err := (spec.Spec{}).ReadData(enc.NewWireView(response))
			require.NoError(t, err)
			require.True(t, data.Name().Equal(interest.Name()))
			require.Equal(t, []byte("accepted"), data.Content().Join())
			repoCert, _, err := (spec.Spec{}).ReadData(enc.NewWireView(repoCertWire))
			require.NoError(t, err)
			valid, err := signer.ValidateData(data, covered, repoCert)
			require.NoError(t, err)
			require.True(t, valid)
		})
	}
}
