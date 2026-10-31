package ndncert

import (
	"crypto/ecdh"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

// The functions defined in this file implement the client protocol for the NDNCERT protocol.
// For most use cases, it is recommended to use the high-level Request API instead.

// FetchProfile fetches the profile from the CA (blocking).
func (c *Client) FetchProfile() (*tlv.CaProfile, error) {
	// TODO: validate packets received by the client using the cert.
	ch := make(chan ndn.ConsumeState)
	name := c.caPrefix.
		Append(enc.NewGenericComponent("CA")).
		Append(enc.NewGenericComponent("INFO"))
	c.client.Consume(name, func(status ndn.ConsumeState) { ch <- status })
	state := <-ch
	if err := state.Error(); err != nil {
		return nil, err
	}

	return tlv.ParseCaProfile(enc.NewWireView(state.Content()), false)
}

// FetchProbe sends a PROBE request to the CA (blocking).
func (c *Client) FetchProbe(params ParamMap) (*tlv.ProbeRes, error) {
	probeParams := tlv.ProbeReq{Params: params}

	ch := make(chan ndn.ExpressCallbackArgs, 1)
	c.client.ExpressR(ndn.ExpressRArgs{
		Name: c.caPrefix.Append(
			enc.NewGenericComponent("CA"),
			enc.NewGenericComponent("PROBE"),
		),
		Config: &ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		AppParam: probeParams.Encode(),
		Signer:   sig.NewSha256Signer(),
		Retries:  3,
		Callback: func(args ndn.ExpressCallbackArgs) { ch <- args },
	})
	args := <-ch
	if args.Result != ndn.InterestResultData {
		return nil, fmt.Errorf("failed to fetch probe response: %s (%w)", args.Result, args.Error)
	}

	if err := c.validate(args); err != nil {
		return nil, err
	}

	content := args.Data.Content()
	if err := IsError(content); err != nil {
		return nil, err
	}

	return tlv.ParseProbeRes(enc.NewWireView(content), false)
}

// FetchProbeRedirect sends a PROBE request to the CA (blocking).
// If a redirect is received, the request is sent to the new location.
func (c *Client) FetchProbeRedirect(params ParamMap) (probe *tlv.ProbeRes, err error) {
	for i := 0; i < 4; i++ {
		probe, err = c.FetchProbe(params)
		if err != nil {
			return nil, err
		}

		// Check if the probe response is a redirect
		if probe.RedirectPrefix == nil ||
			len(probe.RedirectPrefix.Name) == 0 ||
			probe.RedirectPrefix.Name.Equal(c.caPrefix) {
			// Found last CA in the chain
			return probe, nil
		}

		// Redirect to a different CA
		caCert := probe.RedirectPrefix.Name
		caPrefix, err := sec.GetIdentityFromCertName(caCert)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect %s: %w", caCert, err)
		}

		// Check if the name has implicit digest
		if caCert[len(caCert)-1].Typ != enc.TypeImplicitSha256DigestComponent {
			return nil, fmt.Errorf("redirect name must have implicit digest: %s", caCert)
		}

		// Fetch the CA certificate.
		// The certificate name received here includes the implicit digest,
		// so we don't need to validate the received redirect certificate.
		caCertData, _, err := c.fetchCert(caCert, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch CA certificate: %w", err)
		}

		// Update the client to use the new CA
		c.caCert = caCertData
		c.caPrefix = caPrefix
	}

	return nil, fmt.Errorf("too many redirects")
}

// (AI GENERATED DESCRIPTION): New sends the NEW request for this certificate session (blocking).
func (s *Session) New(challenge Challenge, expiry time.Time) (*tlv.NewRes, error) {
	if s == nil {
		return nil, fmt.Errorf("invalid certificate session")
	}
	if s.state != sessionStateReady {
		return nil, fmt.Errorf("certificate session has already attempted NEW")
	}
	if s.network == nil || s.ecdhKey == nil || s.aeadCtr == nil {
		return nil, fmt.Errorf("invalid certificate session")
	}
	if challenge == nil {
		return nil, fmt.Errorf("challenge is required")
	}
	s.state = sessionStateNewAttempted
	defer func() { s.ecdhKey = nil }()

	// Generate self-signed cert as CSR
	csr, err := sec.SelfSign(sec.SignCertArgs{
		Signer:    s.signer,
		NotBefore: time.Now(),
		NotAfter:  expiry,
	})
	if err != nil {
		return nil, err
	}

	// Send NEW request to CA
	newParams := tlv.NewReq{
		EcdhPub: s.ecdhKey.Public().(*ecdh.PublicKey).Bytes(),
		CertReq: csr,
	}

	ch := make(chan ndn.ExpressCallbackArgs, 1)
	s.network.ExpressR(ndn.ExpressRArgs{
		Name: s.caPrefix.Append(
			enc.NewGenericComponent("CA"),
			enc.NewGenericComponent("NEW"),
		),
		Config: &ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		AppParam: newParams.Encode(),
		Signer:   s.signer,
		Retries:  3,
		Callback: func(args ndn.ExpressCallbackArgs) { ch <- args },
	})
	args := <-ch
	if args.Result != ndn.InterestResultData {
		return nil, fmt.Errorf("failed NEW fetch: %s (%w)", args.Result, args.Error)
	}

	if err := s.validate(args); err != nil {
		return nil, err
	}

	content := args.Data.Content()
	if err := IsError(content); err != nil {
		return nil, fmt.Errorf("failed NEW: %w", err)
	}

	newRes, err := tlv.ParseNewRes(enc.NewWireView(content), false)
	if err != nil {
		return nil, err
	}

	// Check if challenge is supported
	hasChallenge := false
	for _, chName := range newRes.Challenge {
		if chName == challenge.Name() {
			hasChallenge = true
			break
		}
	}
	if !hasChallenge && challenge.Name() != KwPin { // pin is always supported
		return nil, fmt.Errorf("challenge not supported by CA: %s", challenge.Name())
	}

	symkey, err := EcdhHkdf(s.ecdhKey, newRes.EcdhPub, newRes.Salt, newRes.ReqId)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}
	s.aesKey = [AeadSizeTag]byte(symkey)
	s.requestID = append([]byte(nil), newRes.ReqId...)
	s.challenge = challenge
	s.state = sessionStateChallenge
	return newRes, nil
}

// (AI GENERATED DESCRIPTION): Challenge completes the CHALLENGE exchange for this certificate session (blocking).
func (s *Session) Challenge() (*tlv.ChallengeRes, error) {
	if s == nil || s.state != sessionStateChallenge {
		return nil, fmt.Errorf("successful NEW required before CHALLENGE")
	}

	var prevRes *tlv.ChallengeRes
	for {
		chRes, err := s.challengeRound(prevRes)
		if err != nil {
			return nil, err
		}

		switch ChallengeStatus(chRes.Status) {
		case ChallengeStatusBefore:
			return chRes, ErrChallengeBefore
		case ChallengeStatusChallenge:
			prevRes = chRes
		case ChallengeStatusPending:
			// TODO: likely need to wait and retry
			return chRes, ErrChallengePending
		case ChallengeStatusSuccess:
			return chRes, nil
		case ChallengeStatusFailure:
			return chRes, ErrChallengeFailed
		default:
			return chRes, ErrChallengeStatusUnknown
		}
	}
}

func (s *Session) challengeRound(prevRes *tlv.ChallengeRes) (*tlv.ChallengeRes, error) {
	var prevParams ParamMap = nil
	var prevStatus optional.Optional[string]

	if prevRes != nil {
		prevStatus = prevRes.ChalStatus

		switch ChallengeStatus(prevRes.Status) {
		case ChallengeStatusChallenge:
			// Always provide params (even if they are empty) to the challenge
			prevParams = prevRes.Params
			if prevParams == nil {
				prevParams = make(ParamMap)
			}
		default:
			return nil, fmt.Errorf("invalid challenge status: %d", prevRes.Status)
		}
	}

	// Get challenge params
	params, err := s.challenge.Request(prevParams, prevStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge params: %w", err)
	}

	// Create CHALLENGE request for CA
	chParams := tlv.ChallengeReq{
		Challenge: s.challenge.Name(),
		Params:    params,
	}

	// Encrypt and send CHALLENGE request
	chParamsC, err := AeadEncrypt(
		s.aesKey, chParams.Encode().Join(),
		s.requestID, s.aeadCtr)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt CHALLENGE: %w", err)
	}

	// TODO: implement retrying on failure
	// ExpressR will sign the packet again failure, this breaks the protocol
	ch := make(chan ndn.ExpressCallbackArgs, 1)
	s.network.ExpressR(ndn.ExpressRArgs{
		Name: s.caPrefix.Append(
			enc.NewGenericComponent("CA"),
			enc.NewGenericComponent("CHALLENGE"),
			enc.NewGenericBytesComponent(s.requestID),
		),
		Config: &ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		AppParam: chParamsC.TLV().Encode(),
		Signer:   s.signer,
		Retries:  0,
		Callback: func(args ndn.ExpressCallbackArgs) { ch <- args },
	})
	args := <-ch
	if args.Result != ndn.InterestResultData {
		return nil, fmt.Errorf("failed CHALLENGE fetch: %s (%w)", args.Result, args.Error)
	}

	if err := s.validate(args); err != nil {
		return nil, err
	}

	content := args.Data.Content()
	if err := IsError(content); err != nil {
		return nil, fmt.Errorf("failed CHALLENGE: %w", err)
	}

	chResEnc, err := tlv.ParseCipherMsg(enc.NewWireView(content), false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CHALLENGE cipher response: %w", err)
	}

	chResAeadMsg := AeadMessage{}
	if err := chResAeadMsg.FromTLV(chResEnc); err != nil {
		return nil, fmt.Errorf("invalid CHALLENGE cipher response: %w", err)
	}
	chResBytes, err := AeadDecrypt(s.aesKey, chResAeadMsg, s.requestID, s.aeadCtr)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CHALLENGE response: %w", err)
	}

	chRes, err := tlv.ParseChallengeRes(enc.NewBufferView(chResBytes), false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CHALLENGE response: %w", err)
	}

	return chRes, nil
}

// FetchIssuedCert fetches the issued certificate from the CA (blocking).
func (c *Client) FetchIssuedCert(chRes *tlv.ChallengeRes) (ndn.Data, enc.Wire, error) {
	if chRes.Status != uint64(ChallengeStatusSuccess) {
		return nil, nil, fmt.Errorf("invalid challenge status: %d", chRes.Status)
	}

	if chRes.CertName == nil {
		return nil, nil, fmt.Errorf("missing certificate name")
	}

	// Challenge response may contain a forwarding hint
	var fwHint []enc.Name
	if chRes.ForwardingHint != nil {
		fwHint = []enc.Name{chRes.ForwardingHint.Name}
	}

	// Fetch issued certificate
	return c.fetchCert(chRes.CertName.Name, fwHint)
}

// fetchCert fetches a certificate from the network.
func (c *Client) fetchCert(name enc.Name, fwHint []enc.Name) (ndn.Data, enc.Wire, error) {
	ch := make(chan ndn.ExpressCallbackArgs, 1)
	c.client.ExpressR(ndn.ExpressRArgs{
		Name: name,
		Config: &ndn.InterestConfig{
			CanBePrefix:    false,
			ForwardingHint: fwHint,
		},
		Retries:  3,
		Callback: func(args ndn.ExpressCallbackArgs) { ch <- args },
	})
	args := <-ch
	if args.Result != ndn.InterestResultData {
		return nil, nil, fmt.Errorf("failed to fetch cert: %s (%w)", args.Result, args.Error)
	}
	return args.Data, args.RawData, nil
}

// validate checks the signature of the data.
func (c *Client) validate(args ndn.ExpressCallbackArgs) error {
	return validate(args, c.caCert)
}

func (s *Session) validate(args ndn.ExpressCallbackArgs) error {
	return validate(args, s.caCert)
}

func validate(args ndn.ExpressCallbackArgs, cert ndn.Data) error {
	valid, err := sig.ValidateData(args.Data, args.SigCovered, cert)
	if err != nil || !valid {
		return fmt.Errorf("validation failure for %s: %w", args.Data.Name(), err)
	}
	return nil
}
