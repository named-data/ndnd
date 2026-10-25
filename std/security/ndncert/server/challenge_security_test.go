package server

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/stretchr/testify/require"
)

type challengeFixture struct {
	ca      *CaServer
	state   *RequestState
	client  ndn.Signer
	counter *ndncert.AeadCounter
}

func newChallengeFixture(t *testing.T, identity string) challengeFixture {
	t.Helper()
	caKey, err := enc.NameFromStr("/example/KEY/ca")
	require.NoError(t, err)
	caSigner, err := signer.KeygenEd25519(caKey)
	require.NoError(t, err)
	ca, err := NewCaServer(engine.NewBasicEngine(face.NewDummyFace()), &CaConfig{
		CaPrefix: "/example", MaxValidityPeriod: "3600",
		NameAssignment:      map[string]string{ndncert.KwEmail: "/"},
		SupportedChallenges: []ChallengeConfig{{Name: ndncert.KwEmail}, {Name: ndncert.KwDns}},
	}, nil, caSigner)
	require.NoError(t, err)
	name, err := enc.NameFromStr(identity)
	require.NoError(t, err)
	client, err := signer.KeygenEd25519(security.MakeKeyName(name))
	require.NoError(t, err)
	secret, err := signer.MarshalSecretToData(client)
	require.NoError(t, err)
	csr, err := security.SignCert(security.SignCertArgs{
		Data: secret, Signer: client, IssuerId: enc.NewGenericComponent("self"),
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute),
	})
	require.NoError(t, err)
	parsed, _, err := spec.Spec{}.ReadData(enc.NewWireView(csr))
	require.NoError(t, err)
	state := NewRequestState([]byte("request"), ca.caPrefix)
	state.CertRequest, state.RequestedCertName = csr, parsed.Name()
	state.AeadCounter = ndncert.NewAeadCounter()
	require.NoError(t, ca.storage.Put(state.RequestID, state))
	return challengeFixture{ca, state, client, ndncert.NewAeadCounter()}
}

func (f challengeFixture) encrypt(t *testing.T, challenge string, params ndncert.ParamMap) enc.Wire {
	t.Helper()
	plaintext := (&tlv.ChallengeReq{Challenge: challenge, Params: params}).Encode()
	message, err := ndncert.AeadEncrypt(f.state.AesKey, plaintext.Join(), f.state.RequestID, f.counter)
	require.NoError(t, err)
	return message.TLV().Encode()
}

func (f challengeFixture) args(t *testing.T, body enc.Wire, key ndn.Signer) (ndn.InterestHandlerArgs, <-chan enc.Wire) {
	t.Helper()
	packet, err := spec.Spec{}.MakeInterest(f.ca.caPrefix.Append(
		enc.NewGenericComponent("CA"), enc.NewGenericComponent("CHALLENGE"),
		enc.NewGenericBytesComponent(f.state.RequestID)), &ndn.InterestConfig{}, body, key)
	require.NoError(t, err)
	interest, covered, err := spec.Spec{}.ReadInterest(enc.NewWireView(packet.Wire))
	require.NoError(t, err)
	responses := make(chan enc.Wire, 1)
	return ndn.InterestHandlerArgs{Interest: interest, SigCovered: covered,
		Reply: func(wire enc.Wire) error { responses <- wire; return nil }}, responses
}

func readChallengeResponse(t *testing.T, responses <-chan enc.Wire) enc.Wire {
	t.Helper()
	select {
	case wire := <-responses:
		packet, _, err := spec.Spec{}.ReadData(enc.NewWireView(wire))
		require.NoError(t, err)
		return packet.Content()
	case <-time.After(2 * time.Second):
		t.Fatal("CHALLENGE handler did not reply")
		return nil
	}
}

func requireChallengeError(t *testing.T, content enc.Wire, code uint64) {
	t.Helper()
	response, err := tlv.ParseErrorRes(enc.NewWireView(content), false)
	require.NoError(t, err)
	require.Equal(t, code, response.ErrCode, response.ErrInfo)
}

func (f challengeFixture) response(t *testing.T, content enc.Wire) *tlv.ChallengeRes {
	t.Helper()
	cipher, err := tlv.ParseCipherMsg(enc.NewWireView(content), false)
	require.NoError(t, err)
	var message ndncert.AeadMessage
	require.NoError(t, message.FromTLV(cipher))
	plain, err := ndncert.AeadDecrypt(f.state.AesKey, message, f.state.RequestID)
	require.NoError(t, err)
	response, err := tlv.ParseChallengeRes(enc.NewBufferView(plain), false)
	require.NoError(t, err)
	return response
}

func TestChallengeIssuesOnlyTheVerifiedEmailOrDomain(t *testing.T) {
	for _, challenge := range []string{ndncert.KwEmail, ndncert.KwDns} {
		t.Run(challenge, func(t *testing.T) {
			identity := "/example/org/example/alice"
			params := ndncert.ParamMap{ndncert.KwEmail: []byte("alice@example.org")}
			if challenge == ndncert.KwDns {
				identity = "/example/example.org"
				params = ndncert.ParamMap{ndncert.KwDomain: []byte("example.org")}
			}
			f := newChallengeFixture(t, identity)
			sender := &recordingEmailSender{}
			f.ca.SetEmailSender(sender)
			f.ca.DNSResolver = func(name string) ([]string, error) {
				require.Equal(t, "_ndncert-challenge.example.org", name)
				return []string{base64.StdEncoding.EncodeToString(f.state.ChallengeState["token"])}, nil
			}
			args, replies := f.args(t, f.encrypt(t, challenge, params), f.client)
			f.ca.handleChallenge(args)
			progress := f.response(t, readChallengeResponse(t, replies))
			require.Equal(t, StatusChallenge, progress.Status)
			code := strings.TrimPrefix(strings.Split(sender.body, "\n")[0], "Your NDNCERT verification code is: ")
			params = ndncert.ParamMap{ndncert.KwCode: []byte(code)}
			if challenge == ndncert.KwDns {
				params = ndncert.ParamMap{ndncert.KwConfirmation: []byte("ready")}
			}
			body := f.encrypt(t, challenge, params)
			args, replies = f.args(t, body, f.client)
			f.ca.handleChallenge(args)
			response := f.response(t, readChallengeResponse(t, replies))
			require.Equal(t, StatusSuccess, response.Status)
			require.NotNil(t, response.CertName)
			issued, _, err := spec.Spec{}.ReadData(enc.NewWireView(f.state.IssuedCert))
			require.NoError(t, err)
			got, err := security.GetIdentityFromCertName(issued.Name())
			require.NoError(t, err)
			require.Equal(t, identity, got.String())
			// A completed request cannot issue another certificate on replay.
			args, replies = f.args(t, body, f.client)
			f.ca.handleChallenge(args)
			requireChallengeError(t, readChallengeResponse(t, replies), 9)
		})
	}
}

func TestChallengeIdentityPolicy(t *testing.T) {
	for _, tc := range []struct {
		challenge, identity, value string
		allowed                    bool
	}{
		{"email", "/example/org/example/alice", "alice@example.org", true},
		{"email", "/example/org/example/victim", "attacker@example.org", false},
		{"email", "/example/org/example/alice/child", "alice@example.org", false},
		{"dns", "/example/example.org", "example.org", true},
		{"dns", "/example/victim.org", "attacker.org", false},
		{"dns", "/example/example.org/child", "example.org", false},
		{"dns", "/example/example.org", "example.org/child", false},
		{"dns", "/example/Example.org", "Example.org", false},
	} {
		t.Run(tc.challenge+":"+tc.identity, func(t *testing.T) {
			f := newChallengeFixture(t, tc.identity)
			key := ndncert.KwEmail
			if tc.challenge == ndncert.KwDns {
				key = ndncert.KwDomain
			}
			err := f.ca.validateChallengeIdentity(tc.challenge, ndncert.ParamMap{key: []byte(tc.value)}, f.state)
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	f := newChallengeFixture(t, "/example/org/example/alice")
	f.ca.config.NameAssignment = nil
	require.ErrorContains(t, f.ca.validateChallengeIdentity("email", ndncert.ParamMap{
		ndncert.KwEmail: []byte("alice@example.org"),
	}, f.state), "not configured")
}

func TestChallengeRejectsUnrelatedEmailBeforeSending(t *testing.T) {
	f := newChallengeFixture(t, "/example/org/example/victim")
	sender := &recordingEmailSender{}
	f.ca.SetEmailSender(sender)
	body := f.encrypt(t, "email", ndncert.ParamMap{ndncert.KwEmail: []byte("attacker@example.org")})
	args, replies := f.args(t, body, f.client)
	f.ca.handleChallenge(args)
	requireChallengeError(t, readChallengeResponse(t, replies), 11)
	require.Zero(t, sender.calls)
	require.Equal(t, StatusBeforeChallenge, f.state.Status)
}

func TestChallengeRejectsWrongSignerAndMalformedCipher(t *testing.T) {
	f := newChallengeFixture(t, "/example/org/example/alice")
	other, err := signer.KeygenEd25519(security.MakeKeyName(f.ca.caPrefix))
	require.NoError(t, err)
	body := f.encrypt(t, "email", ndncert.ParamMap{ndncert.KwEmail: []byte("alice@example.org")})
	for _, key := range []ndn.Signer{other, signer.NewSha256Signer(), nil} {
		args, replies := f.args(t, body, key)
		f.ca.handleChallenge(args)
		requireChallengeError(t, readChallengeResponse(t, replies), 7)
		require.False(t, f.state.hasReceivedIV)
	}
	// A matching key locator alone is not authentication: a bad signature must
	// fail before it can advance the receive counter.
	args, replies := f.args(t, body, f.client)
	covered := append([]byte(nil), args.SigCovered.Join()...)
	covered[len(covered)-1] ^= 1
	args.SigCovered = enc.Wire{covered}
	f.ca.handleChallenge(args)
	requireChallengeError(t, readChallengeResponse(t, replies), 7)
	require.False(t, f.state.hasReceivedIV)
	for _, sizes := range [][2]int{{11, 16}, {12, 15}} {
		bad := (&tlv.CipherMsg{InitVec: make([]byte, sizes[0]), AuthNTag: make([]byte, sizes[1]), Payload: []byte{1}}).Encode()
		args, replies := f.args(t, bad, f.client)
		require.NotPanics(t, func() { f.ca.handleChallenge(args) })
		requireChallengeError(t, readChallengeResponse(t, replies), 10)
	}
}

func TestChallengeReplayDoesNotConsumeAnotherAttempt(t *testing.T) {
	f := newChallengeFixture(t, "/example/org/example/alice")
	sender := &recordingEmailSender{}
	f.ca.SetEmailSender(sender)
	initial := f.encrypt(t, "email", ndncert.ParamMap{ndncert.KwEmail: []byte("alice@example.org")})
	args, replies := f.args(t, initial, f.client)
	f.ca.handleChallenge(args)
	readChallengeResponse(t, replies)
	require.Equal(t, 1, sender.calls)
	require.Equal(t, StatusChallenge, f.state.Status)
	// The actual code is deliberately unavailable to this test client.
	badCode := ndncert.ParamMap{ndncert.KwCode: []byte("not-a-code")}
	wrong := f.encrypt(t, "email", badCode)
	args, replies = f.args(t, wrong, f.client)
	f.ca.handleChallenge(args)
	readChallengeResponse(t, replies)
	require.Equal(t, 1, f.state.ChallengeAttempts)
	args, replies = f.args(t, wrong, f.client)
	f.ca.handleChallenge(args)
	requireChallengeError(t, readChallengeResponse(t, replies), 10)
	require.Equal(t, 1, f.state.ChallengeAttempts)
	// Even a newly signed retransmission must not repeat the state transition.
	args, replies = f.args(t, initial, f.client)
	f.ca.handleChallenge(args)
	requireChallengeError(t, readChallengeResponse(t, replies), 10)
	require.Equal(t, 1, sender.calls)
	args, replies = f.args(t, f.encrypt(t, "email", badCode), f.client)
	f.ca.handleChallenge(args)
	readChallengeResponse(t, replies)
	require.Equal(t, 2, f.state.ChallengeAttempts)
}

func TestChallengeReceiveCounterAuthenticatesBeforeAdvancing(t *testing.T) {
	f := newChallengeFixture(t, "/example/org/example/alice")
	message := f.encrypt(t, "email", ndncert.ParamMap{ndncert.KwCode: []byte("x")})
	parsed, err := tlv.ParseCipherMsg(enc.NewWireView(message), false)
	require.NoError(t, err)
	parsed.AuthNTag = append([]byte(nil), parsed.AuthNTag...)
	parsed.AuthNTag[0] ^= 1
	_, _, err = f.ca.decryptChallengeParams(parsed.Encode(), f.state)
	require.Error(t, err)
	require.False(t, f.state.hasReceivedIV)
	_, _, err = f.ca.decryptChallengeParams(message, f.state)
	require.NoError(t, err)
	// A new, correctly authenticated IV prefix is not allowed within a request.
	newPrefix := f.encryptWithCounter(t, ndncert.NewAeadCounter())
	_, _, err = f.ca.decryptChallengeParams(newPrefix, f.state)
	require.Error(t, err)
	// Replaying an old authenticated counter is rejected as well.
	_, _, err = f.ca.decryptChallengeParams(message, f.state)
	require.Error(t, err)
	require.NotZero(t, binary.LittleEndian.Uint32(f.state.receivedIV[ndncert.AeadSizeRand:]))
}

func (f challengeFixture) encryptWithCounter(t *testing.T, counter *ndncert.AeadCounter) enc.Wire {
	t.Helper()
	f.counter = counter
	return f.encrypt(t, "email", ndncert.ParamMap{ndncert.KwCode: []byte("x")})
}

type blockingEmailSender struct {
	started chan struct{}
	release chan struct{}
}

type discardEmailSender struct{}

func (discardEmailSender) Send(string, string, string) error { return nil }

func TestChallengesOnDifferentRequestsRunConcurrently(t *testing.T) {
	first := newChallengeFixture(t, "/example/org/example/alice")
	first.ca.SetEmailSender(discardEmailSender{})
	var fixtures []challengeFixture
	var responses []<-chan enc.Wire
	for i := range 8 {
		f := newChallengeFixture(t, "/example/org/example/alice")
		f.ca = first.ca
		f.state.RequestID = []byte(fmt.Sprintf("request-%d", i))
		require.NoError(t, f.ca.storage.Put(f.state.RequestID, f.state))
		body := f.encrypt(t, "email", ndncert.ParamMap{ndncert.KwEmail: []byte("alice@example.org")})
		args, replies := f.args(t, body, f.client)
		fixtures = append(fixtures, f)
		responses = append(responses, replies)
		f.ca.onChallenge(args)
	}
	for i, reply := range responses {
		response := fixtures[i].response(t, readChallengeResponse(t, reply))
		require.Equal(t, StatusChallenge, response.Status)
	}
}

func (s *blockingEmailSender) Send(string, string, string) error {
	close(s.started)
	<-s.release
	return nil
}

func TestChallengeNetworkIOIsBoundedAndDoesNotBlockOtherRequests(t *testing.T) {
	f := newChallengeFixture(t, "/example/org/example/alice")
	sender := &blockingEmailSender{make(chan struct{}), make(chan struct{})}
	f.ca.SetEmailSender(sender)
	body := f.encrypt(t, "email", ndncert.ParamMap{ndncert.KwEmail: []byte("alice@example.org")})
	args, replies := f.args(t, body, f.client)
	defer func() {
		close(sender.release)
		readChallengeResponse(t, replies)
		f.state.mu.Lock()
		f.state.mu.Unlock()
	}()
	returned := make(chan struct{})
	go func() { f.ca.onChallenge(args); close(returned) }()
	select {
	case <-sender.started:
	case <-time.After(time.Second):
		t.Fatal("SMTP worker did not start")
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("SMTP blocked the engine handler")
	}
	// A second request on the same state is rejected, not queued behind SMTP.
	args2, replies2 := f.args(t, body, f.client)
	f.ca.onChallenge(args2)
	requireChallengeError(t, readChallengeResponse(t, replies2), 100)
	// INFO remains responsive while SMTP is blocked.
	info, err := spec.Spec{}.MakeData(f.ca.caPrefix, &ndn.DataConfig{}, nil, f.ca.signer)
	require.NoError(t, err)
	require.NoError(t, f.ca.objectStore.Put(f.ca.caPrefix, info.Wire.Join()))
	interest, err := spec.Spec{}.MakeInterest(f.ca.caPrefix, &ndn.InterestConfig{}, nil, nil)
	require.NoError(t, err)
	parsed, _, err := spec.Spec{}.ReadInterest(enc.NewWireView(interest.Wire))
	require.NoError(t, err)
	replied := false
	f.ca.onInfo(ndn.InterestHandlerArgs{Interest: parsed, Reply: func(enc.Wire) error { replied = true; return nil }})
	require.True(t, replied)
	// The global limit rejects overflow without starting any extra worker.
	for len(f.ca.challengeSlots) < cap(f.ca.challengeSlots) {
		f.ca.challengeSlots <- struct{}{}
	}
	f.ca.onChallenge(args2)
	requireChallengeError(t, readChallengeResponse(t, replies2), 100)
}

func TestRequestExpiryConcurrentWithCleanup(t *testing.T) {
	store := NewMemoryStorage()
	state := NewRequestState([]byte("request"), nil)
	require.NoError(t, store.Put(state.RequestID, state))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 1000 {
			state.SetExpiresAt(time.Now().Add(time.Hour))
		}
	}()
	go func() {
		defer wg.Done()
		for range 1000 {
			_, _ = store.CleanExpired()
			_, _ = store.Get(state.RequestID)
		}
	}()
	wg.Wait()
	got, err := store.Get(state.RequestID)
	require.NoError(t, err)
	require.Same(t, state, got)
}

func TestDNSFailedLookupsAndMismatchesExhaustAttempts(t *testing.T) {
	for _, lookupError := range []bool{false, true} {
		t.Run(fmt.Sprint(lookupError), func(t *testing.T) {
			state := NewRequestState([]byte("request"), nil)
			handler := &ChallengeDnsHandler{DNSResolver: func(string) ([]string, error) {
				if lookupError {
					return nil, fmt.Errorf("lookup unavailable")
				}
				return []string{"wrong"}, nil
			}}
			_, _, err := handler.HandleChallenge(ndncert.ParamMap{ndncert.KwDomain: []byte("example.org")}, state)
			require.NoError(t, err)
			for remaining := 2; remaining >= 0; remaining-- {
				_, status, err := handler.HandleChallenge(ndncert.ParamMap{ndncert.KwConfirmation: []byte("ready")}, state)
				require.NoError(t, err)
				require.Equal(t, "wrong-record", status)
				require.Equal(t, remaining, state.RemainingAttempts())
			}
			require.Equal(t, StatusFailure, state.Status)
		})
	}
}
