package ndncert

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	sig "github.com/named-data/ndnd/std/security/signer"
)

type Client struct {
	engine ndn.Engine
	signer ndn.Signer

	caCert   ndn.Data
	caPrefix enc.Name

	client  ndn.Client
	ecdhKey *ecdh.PrivateKey
	aeadCtr *AeadCounter
}

// NewClient creates a new NDNCERT client.
//
//	engine: NDN engine
//	caCert: CA certificate raw wire
//	signer: signer for the client
func NewClient(engine ndn.Engine, caCert []byte) (*Client, error) {
	// Decode CA certificate
	cert, _, err := engine.Spec().ReadData(enc.NewBufferView(caCert))
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA certificate: %w", err)
	}

	// Object API client for network requests. We use our own client here
	// because this needs a custom trust model that is not the same as app.
	// No need to start the client because it is only used for consume.
	// TODO: find a better way to express this and prevent the error
	// returned by start due to multiple clients.
	client := object.NewClient(engine, storage.NewMemoryStore(), nil)

	// Generate ECDH Key used for encryption
	ecdhKey, err := EcdhKeygen()
	if err != nil {
		return nil, err
	}

	// Get CA prefix from CA certificate
	caPrefix, err := sec.GetIdentityFromCertName(cert.Name())
	if err != nil {
		return nil, fmt.Errorf("invalid CA certificate name: %w", err)
	}

	return &Client{
		engine: engine,

		caCert:   cert,
		caPrefix: caPrefix,

		client:  client,
		ecdhKey: ecdhKey,
		aeadCtr: NewAeadCounter(),
	}, nil
}

// SetSigner sets the signer for the client.
func (c *Client) SetSigner(signer ndn.Signer) {
	c.signer = signer
}

// CaPrefix returns the CA prefix.
func (c *Client) CaPrefix() enc.Name {
	return c.caPrefix
}

// RequestCertArgs is the arguments for the Issue function.
type RequestCertArgs struct {
	// Challenge is the challenge to be used for the certificate request.
	Challenge Challenge
	// OnProfile is called when a CA profile is fetched.
	// Returning an error will abort the request.
	OnProfile func(profile *tlv.CaProfile) error
	// DisableProbe is a flag to disable the probe step.
	// If true, the key will be used directly.
	DisableProbe bool
	// OnProbeParam is the callback to get the probe parameter.
	// Returning an error will abort the request.
	OnProbeParam func(key string) ([]byte, error)
	// OnChooseKey is the callback to choose a key suggestion.
	// Returning an invalid index will abort the request.
	// If nil, the first suggestion is used.
	OnChooseKey func(suggestions []enc.Name) int
	// OnKeyChosen is called when a key is chosen.
	// Returning an error will abort the request.
	OnKeyChosen func(keyName enc.Name) error
}

// RequestCertResult is the result of the Issue function.
type RequestCertResult struct {
	// CertData is the issued certificate data.
	CertData ndn.Data
	// CertWire is the raw certificate data.
	CertWire enc.Wire
	// Signer is the signer used for the certificate.
	Signer ndn.Signer
}

// RequestCert is the high level function to issue a certificate.
// This API is recommended to be used for most cases.
// This is a blocking function and should be called in a separate goroutine.
func (c *Client) RequestCert(args RequestCertArgs) (*RequestCertResult, error) {
	// ======  Step 0: Validate arguments ==============
	if args.Challenge == nil {
		return nil, ndn.ErrInvalidValue{Item: "Challenge", Value: nil}
	}
	if !args.DisableProbe && args.OnProbeParam == nil {
		return nil, ndn.ErrInvalidValue{Item: "ProbeParam", Value: nil}
	}

	// ======  Step 1: INFO CA profile ==============

	// Profile of the CA we will use
	var profile *tlv.CaProfile = nil
	var err error = nil

	// Helper to fetch profile and callback to app
	fetchProfile := func() error {
		profile, err = c.FetchProfile()
		if err != nil {
			return err
		}

		// Call the OnProfile callback
		if args.OnProfile != nil {
			if err := args.OnProfile(profile); err != nil {
				return err
			}
		}
		return nil
	}

	// Fetch root CA profile
	if err := fetchProfile(); err != nil {
		return nil, err
	}

	// ======  Step 2: PROBE CA (optional) ==============

	// Probe is optional, if disabled use the provided key directly
	probe := &tlv.ProbeRes{}

	// Probe the CA and get key suggestions
	if !args.DisableProbe {
		// We expect all CAs to support the same param keys for now.
		// This is a reasonable assumption (for now) at least on testbed.
		probeParams := ParamMap{}
		for _, key := range profile.ParamKey {
			val, err := args.OnProbeParam(key)
			if err != nil {
				return nil, err
			}
			probeParams[key] = val
		}

		// Probe the CA and redirect to the correct CA
		prevCaPrefix := c.CaPrefix()
		probe, err = c.FetchProbeRedirect(probeParams)
		if err != nil {
			return nil, fmt.Errorf("unable to probe the CA: %w", err)
		}

		// Fetch redirected CA profile if changed
		if !c.CaPrefix().Equal(prevCaPrefix) {
			if err := fetchProfile(); err != nil {
				return nil, err
			}
		}
	}

	// Get all probeSgst identity values
	probeSgst := make([]enc.Name, 0, len(probe.Vals))
	for _, sgst := range probe.Vals {
		probeSgst = append(probeSgst, sgst.Response)
	}

	// If a key is provided, check if the name matches
	if c.signer != nil {
		// if no suggestions, assume it's correct
		found := len(probeSgst) == 0

		// find the key name in the suggestions
		keyName := c.signer.KeyName()
		for _, sgst := range probeSgst {
			if sgst.IsPrefix(keyName) {
				found = true
				break
			}
		}

		// if not found, print suggestions and exit
		if !found {
			return nil, ErrSignerProbeMismatch{
				KeyName:   keyName,
				Suggested: probeSgst,
			}
		}
	} else {
		// If no key is provided, generate one from the suggestions
		var identity enc.Name

		if len(probe.Vals) == 0 {
			// No key suggestions, ask the user to provide one
			return nil, ErrNoKeySuggestions
		} else if len(probe.Vals) == 1 {
			// If only one suggestion, use it
			identity = probe.Vals[0].Response
		} else {
			// Multiple available suggestions
			if args.OnChooseKey == nil {
				// Use the first suggestion by default
				identity = probeSgst[0]
			} else {
				// Ask the user to choose a suggestion
				idx := args.OnChooseKey(probeSgst)
				if idx < 0 || idx >= len(probe.Vals) {
					return nil, err
				}
				identity = probeSgst[idx]
			}
		}

		// Generate key
		keyName := sec.MakeKeyName(identity)
		c.signer, err = sig.KeygenEcc(keyName, elliptic.P256())
		if err != nil {
			return nil, err
		}
	}

	// Alert the app that a key has been chosen
	if args.OnKeyChosen != nil {
		if err := args.OnKeyChosen(c.signer.KeyName()); err != nil {
			return nil, err
		}
	}

	// ======  Step 3: NEW ==============
	// Use the longest possible validity period
	expiry := time.Now().Add(time.Second * time.Duration(profile.MaxValidPeriod-300))
	newRes, err := c.New(args.Challenge, expiry)
	if err != nil {
		return nil, err
	}

	// ======  Step 4: CHALLENGE ==============
	chRes, err := c.Challenge(args.Challenge, newRes, nil)
	if err != nil {
		return nil, err
	}
	if chRes.CertName.Name == nil {
		return nil, fmt.Errorf("no issued certificate name after challenge")
	}

	// ======  Step 5: Fetch issued cert ==============
	certData, certWire, err := c.FetchIssuedCert(chRes)
	if err != nil {
		return nil, err
	}

	return &RequestCertResult{
		CertData: certData,
		CertWire: certWire,
		Signer:   c.signer,
	}, nil
}
