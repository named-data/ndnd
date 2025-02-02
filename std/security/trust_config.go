package security

import (
	"fmt"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security/signer"
)

// TrustConfig is the configuration of the trust module.
type TrustConfig struct {
	// mutex is the lock for keychain.
	mutex sync.RWMutex
	// keychain is the keychain.
	keychain ndn.KeyChain
	// schema is the trust schema.
	schema ndn.TrustSchema
	// roots are the full names of the trust anchors.
	roots []enc.Name
}

// NewTrustConfig creates a new TrustConfig.
// ALl roots must be full names and already present in the keychain.
func NewTrustConfig(keyChain ndn.KeyChain, schema ndn.TrustSchema, roots []enc.Name) (*TrustConfig, error) {
	// Check arguments
	if keyChain == nil || schema == nil {
		return nil, fmt.Errorf("keychain and schema must not be nil")
	}

	// Check if we have some roots
	if len(roots) == 0 {
		return nil, fmt.Errorf("no trust anchors provided")
	}

	// Check if all roots are present in the keychain
	for _, root := range roots {
		if cert, _ := keyChain.Store().Get(root, false); cert == nil {
			return nil, fmt.Errorf("trust anchor not found in keychain: %s", root)
		}
	}

	return &TrustConfig{
		mutex:    sync.RWMutex{},
		keychain: keyChain,
		schema:   schema,
		roots:    roots,
	}, nil
}

func (tc *TrustConfig) String() string {
	return "trust-config"
}

// Suggest suggests a signer for a given name.
func (tc *TrustConfig) Suggest(name enc.Name) ndn.Signer {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	return tc.schema.Suggest(name, tc.keychain)
}

// TrustConfigValidateArgs are the arguments for the TrustConfig Validate function.
type TrustConfigValidateArgs struct {
	// Data is the packet to validate.
	Data ndn.Data
	// DataSigCov is the signature covered data wire.
	DataSigCov enc.Wire

	// Fetch is the fetch function to use for fetching certificates.
	Fetch func(enc.Name, *ndn.InterestConfig, ndn.ExpressCallbackFunc)
	// Callback is the callback to call when validation is done.
	Callback func(bool, error)
	// OverrideName is an override for the data name (advanced usage).
	OverrideName enc.Name

	// cert is the certificate to use for validation.
	cert ndn.Data
	// certSigCov is the signature covered certificate wire.
	certSigCov enc.Wire

	// depth is the maximum depth of the validation chain.
	depth int
}

// Validate validates a Data packet using a fetch API.
func (tc *TrustConfig) Validate(args TrustConfigValidateArgs) {
	if args.Data == nil {
		args.Callback(false, fmt.Errorf("data is nil"))
		return
	}

	if len(args.DataSigCov) == 0 {
		args.Callback(false, fmt.Errorf("data sig covered is nil"))
		return
	}

	// Prevent infinite recursion for signer loops
	if args.depth == 0 {
		args.depth = 32
	} else if args.depth <= 1 {
		args.Callback(false, fmt.Errorf("max depth reached"))
		return
	} else {
		args.depth--
	}

	// Make sure the data is signed
	signature := args.Data.Signature()
	if signature == nil {
		args.Callback(false, fmt.Errorf("signature is nil"))
		return
	}

	// If a certificate is provided, go directly to validation
	if args.cert != nil {
		certName := args.cert.Name()
		dataName := args.Data.Name()
		if len(args.OverrideName) > 0 {
			dataName = args.OverrideName
		}

		// Disallow empty names
		if len(dataName) == 0 {
			args.Callback(false, fmt.Errorf("data name is empty"))
			return
		}

		// Check if the data claims to be a root certificate.
		// This breaks the recursion for validation.
		if dataName.Equal(certName) {
			for _, root := range tc.roots {
				if dataName.Equal(root) {
					args.Callback(true, nil)
					return
				}
			}
			args.Callback(false, fmt.Errorf("data claims to be a trust anchor: %s", dataName))
			return
		}

		// Check schema if the key is allowed
		if !tc.schema.Check(dataName, certName) {
			args.Callback(false, fmt.Errorf("key is not allowed: %s signed by %s", dataName, certName))
			return
		}

		// Validate signature on data
		valid, err := signer.ValidateData(args.Data, args.DataSigCov, args.cert)
		if !valid || err != nil {
			args.Callback(false, fmt.Errorf("signature is invalid: %s (%+v)", args.Data.Name(), err))
			return
		}

		if len(args.certSigCov) == 0 {
			args.Callback(false, fmt.Errorf("cert sig covered is nil: %s", certName))
			return
		}

		// Recursively validate the certificate
		tc.Validate(TrustConfigValidateArgs{
			Data:       args.cert,
			DataSigCov: args.certSigCov,

			Fetch:        args.Fetch,
			Callback:     args.Callback,
			OverrideName: nil,

			cert:       nil,
			certSigCov: nil,

			depth: args.depth,
		})
		return
	}

	// Get the key locator
	keyLocator := signature.KeyName()
	if keyLocator == nil {
		args.Callback(false, fmt.Errorf("key locator is nil"))
		return
	}

	// Detect if this is a self-signed certificate, and automatically pick the cert
	// as itself to verify in this case.
	if args.Data.ContentType() != nil && *args.Data.ContentType() == ndn.ContentTypeKey && keyLocator.IsPrefix(args.Data.Name()) {
		args.cert = args.Data
		tc.Validate(args)
		return
	}

	// Attempt to get cert from store.
	// Store is thread-safe so no need to lock here.
	certBytes, err := tc.keychain.Store().Get(keyLocator, true)
	if err != nil {
		log.Error(nil, "Failed to get certificate from store", "err", err)
		args.Callback(false, err)
		return // store is likely broken
	}
	if len(certBytes) > 0 {
		// Attempt to parse the certificate
		args.cert, args.certSigCov, err = spec.Spec{}.ReadData(enc.NewFastBufReader(certBytes))
		if err != nil {
			log.Error(nil, "Failed to parse certificate in store", "err", err)
			args.cert = nil
			args.certSigCov = nil
		}
	}

	// Make sure the certificate is fresh
	if args.cert != nil && CertIsExpired(args.cert) {
		args.cert = nil
		args.certSigCov = nil
	}

	// If not found, attempt to fetch cert from network
	if args.cert == nil {
		log.Debug(tc, "Fetching certificate", "name", keyLocator)
		args.Fetch(keyLocator, &ndn.InterestConfig{
			CanBePrefix: true,
			MustBeFresh: true,
		}, func(res ndn.ExpressCallbackArgs) {
			if res.Error == nil && res.Result != ndn.InterestResultData {
				res.Error = fmt.Errorf("failed to fetch certificate (%s) with result: %s", keyLocator, res.Result)
			}

			if res.Error != nil {
				args.Callback(false, res.Error)
				return // failed to fetch cert
			}

			// Bail if the fetched cert is not fresh
			if CertIsExpired(res.Data) {
				args.Callback(false, fmt.Errorf("certificate is expired: %s", res.Data.Name()))
				return
			}

			// Fetched cert is fresh
			log.Debug(tc, "Fetched certificate from network", "cert", res.Data.Name())

			// Call again with the fetched cert
			args.cert = res.Data
			args.certSigCov = res.SigCovered

			// Monkey patch the callback to store the cert in keychain
			// if the validation passes.
			origCallback := args.Callback
			args.Callback = func(valid bool, err error) {
				if valid && err == nil {
					tc.mutex.Lock()
					err := tc.keychain.InsertCert(res.RawData.Join())
					tc.mutex.Unlock()
					if err != nil {
						log.Error(tc, "Failed to insert certificate to keychain", "name", res.Data.Name(), "err", err)
					}
				} else {
					log.Warn(tc, "Received invalid certificate", "name", res.Data.Name(), "valid", valid, "err", err)
				}
				origCallback(valid, err) // continue validation
			}

			tc.Validate(args)
		})
	} else {
		tc.Validate(args)
	}
}
