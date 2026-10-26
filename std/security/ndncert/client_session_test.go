package ndncert

import (
	"bytes"
	"crypto/elliptic"
	"strings"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	sig "github.com/named-data/ndnd/std/security/signer"
)

type sessionTestClient struct {
	ndn.Client
	express func(ndn.ExpressRArgs)
}

func (c *sessionTestClient) ExpressR(args ndn.ExpressRArgs) { c.express(args) }

func newSessionTestClient(t *testing.T) (*Client, ndn.Signer) {
	t.Helper()
	name, err := enc.NameFromStr("/ca")
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := sig.KeygenEcc(sec.MakeKeyName(name), elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	certWire, err := sec.SelfSign(sec.SignCertArgs{Signer: caSigner, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	caCert, _, err := (spec.Spec{}).ReadData(enc.NewWireView(certWire))
	if err != nil {
		t.Fatal(err)
	}
	identity := name.Append(enc.NewGenericComponent("alice"))
	requester, err := sig.KeygenEcc(sec.MakeKeyName(identity), elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	return &Client{signer: requester, caCert: caCert, caPrefix: name}, caSigner
}

func replySessionTest(t *testing.T, signer ndn.Signer, args ndn.ExpressRArgs, content enc.Wire) {
	t.Helper()
	wire, err := (spec.Spec{}).MakeData(args.Name, &ndn.DataConfig{}, content, signer)
	if err != nil {
		t.Fatal(err)
	}
	data, covered, err := (spec.Spec{}).ReadData(enc.NewWireView(wire.Wire))
	if err != nil {
		t.Fatal(err)
	}
	args.Callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultData, Data: data, SigCovered: covered})
}

func TestClientNewSession(t *testing.T) {
	c, caSigner := newSessionTestClient(t)
	var previousPub []byte
	var previousCounter *AeadCounter
	request := 0
	c.client = &sessionTestClient{express: func(args ndn.ExpressRArgs) {
		params, err := tlv.ParseNewReq(enc.NewWireView(args.AppParam), false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(params.EcdhPub, c.ecdhKey.PublicKey().Bytes()) {
			t.Fatal("NEW does not carry current session public key")
		}
		if bytes.Equal(params.EcdhPub, previousPub) {
			t.Fatal("NEW reused an ephemeral ECDH key")
		}
		if c.aeadCtr == previousCounter || c.aeadCtr.nextSendBlock != 0 {
			t.Fatal("NEW reused IV state")
		}
		previousPub = bytes.Clone(params.EcdhPub)
		previousCounter = c.aeadCtr
		request++
		if request == 2 {
			// A failed NEW must not cause the next attempt to reuse its key.
			args.Callback(ndn.ExpressCallbackArgs{Result: ndn.InterestResultTimeout})
			return
		}
		serverKey, err := EcdhKeygen()
		if err != nil {
			t.Fatal(err)
		}
		response := &tlv.NewRes{EcdhPub: serverKey.PublicKey().Bytes(), Salt: make([]byte, 32), ReqId: make([]byte, 8), Challenge: []string{KwEmail}}
		clientSecret, err := EcdhHkdf(c.ecdhKey, response.EcdhPub, response.Salt, response.ReqId)
		if err != nil {
			t.Fatal(err)
		}
		serverSecret, err := EcdhHkdf(serverKey, params.EcdhPub, response.Salt, response.ReqId)
		if err != nil || !bytes.Equal(clientSecret, serverSecret) {
			t.Fatalf("session key agreement failed: %v", err)
		}
		replySessionTest(t, caSigner, args, response.Encode())
	}}
	for i := 1; i <= 3; i++ {
		_, err := c.New(&ChallengeEmail{}, time.Now().Add(time.Hour))
		if (err != nil) != (i == 2) {
			t.Fatalf("request %d: unexpected error %v", i, err)
		}
		// Exercise reset of both sending and receiving state on reuse.
		c.aeadCtr.nextSendBlock = 100
	}
}

func TestClientNewRejectsRequesterSignedResponse(t *testing.T) {
	c, _ := newSessionTestClient(t)
	serverKey, err := EcdhKeygen()
	if err != nil {
		t.Fatal(err)
	}
	response := &tlv.NewRes{EcdhPub: serverKey.PublicKey().Bytes(), Salt: make([]byte, 32), ReqId: make([]byte, 8), Challenge: []string{KwEmail}}
	c.client = &sessionTestClient{express: func(args ndn.ExpressRArgs) {
		replySessionTest(t, c.signer, args, response.Encode())
	}}
	if _, err := c.New(&ChallengeEmail{}, time.Now().Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "validation failure") {
		t.Fatalf("expected CA signature validation failure, got %v", err)
	}
}

func TestClientChallengeRequiresSession(t *testing.T) {
	if _, err := new(Client).Challenge(&ChallengeEmail{}, nil, nil); err == nil {
		t.Fatal("CHALLENGE accepted without NEW")
	}
}
