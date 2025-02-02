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
	c.client.Consume(name, func(status ndn.ConsumeState) {
		if status.IsComplete() {
			ch <- status
		}
	})
	state := <-ch
	if err := state.Error(); err != nil {
		return nil, err
	}

	return tlv.ParseCaProfile(enc.NewFastReader(state.Content()), false)
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
		return nil, fmt.Errorf("failed to fetch probe response: %s (%+v)", args.Result, args.Error)
	}

	if err := c.validate(args); err != nil {
		return nil, err
	}

	content := args.Data.Content()
	if err := IsError(content); err != nil {
		return nil, err
	}

	return tlv.ParseProbeRes(enc.NewFastReader(content), false)
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
			return nil, fmt.Errorf("invalid redirect %s: %+v", caCert, err)
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
			return nil, fmt.Errorf("failed to fetch CA certificate: %+v", err)
		}

		// Update the client to use the new CA
		c.caCert = caCertData
		c.caPrefix = caPrefix
	}

	return nil, fmt.Errorf("too many redirects")
}

// New sends a NEW request to the CA (blocking).
func (c *Client) New(challenge Challenge, expiry time.Time) (*tlv.NewRes, error) {
	// Signer must be set before this step
	if c.signer == nil {
		return nil, fmt.Errorf("signer not set")
	}

	// Generate self-signed cert as CSR
	csr, err := sec.SelfSign(sec.SignCertArgs{
		Signer:    c.signer,
		NotBefore: time.Now(),
		NotAfter:  expiry,
	})
	if err != nil {
		return nil, err
	}

	// Send NEW request to CA
	newParams := tlv.NewReq{
		EcdhPub: c.ecdhKey.Public().(*ecdh.PublicKey).Bytes(),
		CertReq: csr,
	}

	ch := make(chan ndn.ExpressCallbackArgs, 1)
	c.client.ExpressR(ndn.ExpressRArgs{
		Name: c.caPrefix.Append(
			enc.NewGenericComponent("CA"),
			enc.NewGenericComponent("NEW"),
		),
		Config: &ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		AppParam: newParams.Encode(),
		Signer:   c.signer,
		Retries:  3,
		Callback: func(args ndn.ExpressCallbackArgs) { ch <- args },
	})
	args := <-ch
	if args.Result != ndn.InterestResultData {
		return nil, fmt.Errorf("failed NEW fetch: %s (%+v)", args.Result, args.Error)
	}

	if err := c.validate(args); err != nil {
		return nil, err
	}

	content := args.Data.Content()
	if err := IsError(content); err != nil {
		return nil, fmt.Errorf("failed NEW: %+v", err)
	}

	newRes, err := tlv.ParseNewRes(enc.NewFastReader(content), false)
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

	return newRes, nil
}

// Challenge sends a CHALLENGE request to the CA (blocking).
func (c *Client) Challenge(
	challenge Challenge,
	newRes *tlv.NewRes,
	prevRes *tlv.ChallengeRes,
) (*tlv.ChallengeRes, error) {
	var prevParams ParamMap = nil
	var prevStatus *string = nil

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
	params, err := challenge.Request(prevParams, prevStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge params: %w", err)
	}

	// Create CHALLENGE request for CA
	chParams := tlv.ChallengeReq{
		Challenge: challenge.Name(),
		Params:    params,
	}

	// Derive symmetric key using ECDH-HKDF
	symkey, err := EcdhHkdf(c.ecdhKey, newRes.EcdhPub, newRes.Salt, newRes.ReqId)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	// Encrypt and send CHALLENGE request
	chParamsC, err := AeadEncrypt(
		[16]byte(symkey), chParams.Encode().Join(),
		newRes.ReqId, c.aeadCtr)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt CHALLENGE: %w", err)
	}

	// TODO: implement retrying on failure
	// ExpressR will sign the packet again failure, this breaks the protocol
	ch := make(chan ndn.ExpressCallbackArgs, 1)
	c.client.ExpressR(ndn.ExpressRArgs{
		Name: c.caPrefix.Append(
			enc.NewGenericComponent("CA"),
			enc.NewGenericComponent("CHALLENGE"),
			enc.NewGenericBytesComponent(newRes.ReqId),
		),
		Config: &ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		AppParam: chParamsC.TLV().Encode(),
		Signer:   c.signer,
		Retries:  0,
		Callback: func(args ndn.ExpressCallbackArgs) { ch <- args },
	})
	args := <-ch
	if args.Result != ndn.InterestResultData {
		return nil, fmt.Errorf("failed CHALLENGE fetch: %s (%+v)", args.Result, args.Error)
	}

	if err := c.validate(args); err != nil {
		return nil, err
	}

	content := args.Data.Content()
	if err := IsError(content); err != nil {
		return nil, fmt.Errorf("failed CHALLENGE: %+v", err)
	}

	chResEnc, err := tlv.ParseCipherMsg(enc.NewFastReader(content), false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CHALLENGE cipher response: %w", err)
	}

	chResAeadMsg := AeadMessage{}
	chResAeadMsg.FromTLV(chResEnc)
	chResBytes, err := AeadDecrypt([16]byte(symkey), chResAeadMsg, newRes.ReqId)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CHALLENGE response: %w", err)
	}

	chRes, err := tlv.ParseChallengeRes(enc.NewFastBufReader(chResBytes), false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CHALLENGE response: %w", err)
	}

	switch ChallengeStatus(chRes.Status) {
	case ChallengeStatusBefore:
		return chRes, ErrChallengeBefore
	case ChallengeStatusChallenge:
		// Continue with the challenge
		return c.Challenge(challenge, newRes, chRes)
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
		return nil, nil, fmt.Errorf("failed to fetch cert: %s (%+v)", args.Result, args.Error)
	}
	return args.Data, args.RawData, nil
}

// validate checks the signature of the data.
func (c *Client) validate(args ndn.ExpressCallbackArgs) error {
	valid, err := sig.ValidateData(args.Data, args.SigCovered, c.caCert)
	if err != nil || !valid {
		return fmt.Errorf("validation failure for %s: %+v", args.Data.Name(), err)
	}
	return nil
}
