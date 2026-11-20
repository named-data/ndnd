package ndncert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
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
		if c.aeadCtr == previousCounter || c.aeadCtr.nextSendBlock != 0 || c.aeadCtr.nextPeerBlock != 0 {
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
		c.aeadCtr.nextPeerBlock = 200
	}
}

// Exercise the client protocol against a peer using the standard-library GCM
// API directly, so the client and test peer cannot share an IV-encoding bug.
func TestClientChallengeExchange(t *testing.T) {
	for _, test := range []struct {
		name   string
		replay bool
	}{
		{"two-round success", false},
		{"replayed response", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, caSigner := newSessionTestClient(t)
			serverKey, err := EcdhKeygen()
			if err != nil {
				t.Fatal(err)
			}
			newResponse := &tlv.NewRes{
				EcdhPub: serverKey.PublicKey().Bytes(), Salt: bytes.Repeat([]byte{9}, 32),
				ReqId: []byte("request1"), Challenge: []string{KwEmail},
			}
			var gcm cipher.AEAD
			issuedName := c.signer.KeyName().Append(enc.NewGenericComponent("ca"), enc.NewVersionComponent(1))
			peer := &sessionTestClient{}
			c.client = peer

			// Complete NEW and derive the peer's session key before CHALLENGE.
			peer.express = func(args ndn.ExpressRArgs) {
				req, err := tlv.ParseNewReq(enc.NewWireView(args.AppParam), false)
				if err != nil {
					t.Fatal(err)
				}
				key, err := EcdhHkdf(serverKey, req.EcdhPub, newResponse.Salt, newResponse.ReqId)
				if err != nil {
					t.Fatal(err)
				}
				block, err := aes.NewCipher(key)
				if err != nil {
					t.Fatal(err)
				}
				gcm, err = cipher.NewGCM(block)
				if err != nil {
					t.Fatal(err)
				}
				replySessionTest(t, caSigner, args, newResponse.Encode())
			}
			codesRequested := 0
			challenge := &ChallengeEmail{Email: "a@example.org", CodeCallback: func(status string) string {
				if status != "need-code" {
					t.Fatalf("unexpected challenge status: %s", status)
				}
				codesRequested++
				return "123456"
			}}
			result, err := c.New(challenge, time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}

			// Verify each CHALLENGE request and return an encrypted response.
			var nextSend, nextReceive uint32
			var clientPrefix []byte
			var firstResponse enc.Wire
			rounds := 0
			peer.express = func(args ndn.ExpressRArgs) {
				if rounds >= 2 {
					t.Fatal("client continued after success or replay")
				}
				msg, err := tlv.ParseCipherMsg(enc.NewWireView(args.AppParam), false)
				if err != nil {
					t.Fatal(err)
				}
				if len(msg.InitVec) != 12 || binary.BigEndian.Uint32(msg.InitVec[8:]) != nextReceive {
					t.Fatal("wrong client IV or block counter")
				}
				if clientPrefix == nil {
					clientPrefix = bytes.Clone(msg.InitVec[:8])
				} else if !bytes.Equal(clientPrefix, msg.InitVec[:8]) {
					t.Fatal("client prefix changed")
				}
				plain, err := gcm.Open(nil, msg.InitVec, append(bytes.Clone(msg.Payload), msg.AuthNTag...), newResponse.ReqId)
				if err != nil {
					t.Fatal(err)
				}
				req, err := tlv.ParseChallengeReq(enc.NewBufferView(plain), false)
				if err != nil {
					t.Fatal(err)
				}
				if req.Challenge != KwEmail {
					t.Fatal("wrong challenge")
				}
				param, value := KwEmail, "a@example.org"
				if rounds == 1 {
					param, value = KwCode, "123456"
				}
				if string(req.Params[param]) != value {
					t.Fatalf("wrong %s parameter", param)
				}
				nextReceive += uint32((len(plain) + 15) / 16)
				response := &tlv.ChallengeRes{Status: uint64(ChallengeStatusChallenge), ChalStatus: optional.Some("need-code")}
				if rounds == 1 {
					response = &tlv.ChallengeRes{
						Status:   uint64(ChallengeStatusSuccess),
						CertName: &spec.NameContainer{Name: issuedName},
					}
				}
				// Use a stable prefix guaranteed to differ from the client's.
				iv := make([]byte, 12)
				copy(iv[:8], clientPrefix)
				iv[0] ^= 1
				binary.BigEndian.PutUint32(iv[8:], nextSend)
				plain = response.Encode().Join()
				sealed := gcm.Seal(nil, iv, plain, newResponse.ReqId)
				nextSend += uint32((len(plain) + 15) / 16)
				content := (&tlv.CipherMsg{InitVec: iv, Payload: sealed[:len(plain)], AuthNTag: sealed[len(plain):]}).Encode()
				if rounds == 0 {
					firstResponse = content
				} else if test.replay {
					content = firstResponse
				}
				rounds++
				replySessionTest(t, caSigner, args, content)
			}
			response, err := c.Challenge(challenge, result, nil)
			if test.replay {
				if err == nil || !strings.Contains(err.Error(), "counter was replayed") {
					t.Fatalf("expected replay rejection, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("challenge failed: %v", err)
				}
				if response.Status != uint64(ChallengeStatusSuccess) {
					t.Fatalf("unexpected status: %d", response.Status)
				}
				if response.CertName == nil || !response.CertName.Name.Equal(issuedName) {
					t.Fatal("wrong issued certificate name")
				}
			}
			if rounds != 2 || codesRequested != 1 {
				t.Fatalf("got %d CHALLENGE rounds and %d code requests", rounds, codesRequested)
			}
		})
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
