package security

import (
	"bytes"
	"fmt"
	"sync"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/security/trust_schema"
	"github.com/named-data/ndnd/std/types/optional"
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

	// certCache stores certificate data and the wire needed to identify and
	// revalidate it.
	// Cache hits are revalidated unless the certificate is a trust anchor.
	certCache *CertCache

	// certListCache stores validated CertLists.
	certListCache *CertListCache

	// UseDataNameFwHint enables using the data name as the forwarding hint.
	// This flag is useful depending on application naming structure.
	//
	// When a Data is being verified, every certificate in the chain
	// will be fetched by attaching the original Data name as the
	// forwarding hint to the Interest.
	UseDataNameFwHint bool
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

	// The cache must start with all trust anchors
	certCache := NewCertCache()
	certListCache := NewCertListCache()

	// Check if all roots are present in the keychain
	for _, root := range roots {
		if certBytes, _ := keyChain.Store().Get(root, false); len(certBytes) == 0 {
			return nil, fmt.Errorf("trust anchor not found in keychain: %s", root)
		} else {
			certData, certSigCov, err := spec.Spec{}.ReadData(enc.NewBufferView(certBytes))
			if err != nil {
				return nil, fmt.Errorf("failed to parse trust anchor %s: %w", root, err)
			}
			certCache.put(certData, certSigCov, enc.Wire{certBytes})
		}
	}

	return &TrustConfig{
		mutex:         sync.RWMutex{},
		keychain:      keyChain,
		schema:        schema,
		roots:         roots,
		certCache:     certCache,
		certListCache: certListCache,
	}, nil
}

// (AI GENERATED DESCRIPTION): Returns the constant string `"trust-config"` for a `TrustConfig` value, enabling string formatting via the `fmt.Stringer` interface.
func (tc *TrustConfig) String() string {
	return "trust-config"
}

// Suggest suggests a signer for a given name.
func (tc *TrustConfig) Suggest(name enc.Name) ndn.Signer {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	return tc.schema.Suggest(name, tc.keychain)
}

// SetSchema atomically replaces the trust schema.
func (tc *TrustConfig) SetSchema(schema ndn.TrustSchema) {
	if schema == nil {
		return
	}
	tc.mutex.Lock()
	tc.schema = schema
	tc.mutex.Unlock()
}

// TrustConfigValidateArgs are the arguments for the TrustConfig Validate function.
type TrustConfigValidateArgs struct {
	// Data is the packet to validate.
	Data ndn.Data
	// RawData is the complete wire encoding of Data. It may be nil when the
	// caller only has the parsed packet.
	RawData enc.Wire
	// DataSigCov is the signature covered data wire.
	DataSigCov enc.Wire

	// Fetch is the fetch function to use for fetching certificates.
	// The fetcher MUST check the store for the certificate before fetching.
	Fetch func(enc.Name, *ndn.InterestConfig, ndn.ExpressCallbackFunc)
	// UseDataNameFwHint overrides trust config option.
	UseDataNameFwHint optional.Optional[bool]
	// Callback is the callback to call when validation is done.
	Callback func(bool, error)
	// OverrideName is an override for the data name (advanced usage).
	OverrideName enc.Name
	// OnCertExpired decides whether an expired certificate may be used.
	// A nil callback rejects expired certificates.
	OnCertExpired ndn.CertExpiredCallback
	// origDataName is the original data name being verified.
	origDataName enc.Name
	// crossSchemaExpired indicates Data is an expired cross-schema packet whose
	// use by the original packet was accepted by the expiry policy.
	crossSchemaExpired bool

	// cert is the certificate to use for validation.
	cert ndn.Data
	// certExpiryHandled indicates the expiry policy accepted the current Data/cert relation.
	certExpiryHandled bool
	// certSigCov is the signature covered certificate wire.
	certSigCov enc.Wire
	// certWire is the complete certificate wire used as packet identity.
	certWire enc.Wire
	// certIsValid indicates if the certificate has been already validated.
	certIsValid bool

	// crossSchemaIsValid indicates if the cross schema validation has been already done.
	crossSchemaIsValid bool

	// depth is the maximum depth of the validation chain.
	depth int
}

// runCertExpiryPolicy invokes the policy for a validation relation already known
// to involve an expired validity period. An asynchronous policy may race its
// result against a timeout, so only the first completion resumes validation.
func runCertExpiryPolicy(
	policy ndn.CertExpiredCallback,
	expiryArgs ndn.CertExpiredCallbackArgs,
	resumeValidation func(error),
) {
	if policy == nil {
		policy = RejectExpiredCert // the default
	}
	var resumeOnce sync.Once
	policy(expiryArgs, func(err error) {
		resumeOnce.Do(func() {
			resumeValidation(err)
		})
	})
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

	if args.origDataName == nil {
		// Always use original name here, not the override name
		args.origDataName = args.Data.Name()
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

	// Get the key locator
	keyLocator := signature.KeyName()
	if len(keyLocator) == 0 {
		args.Callback(false, fmt.Errorf("key locator is nil"))
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

		// The same expired, intermidiary certificate would appear in callbacks two times.
		// The first it appears as a signing certificate, asking if the data signing was valid.
		// The second it appears as a data to be validated in the next depth, asking if the certificate issuance was valid.
		// It is the responsibility of the policy to distinguish these two cases be aware of the cross schema usage.
		certDataExpired := false
		if t, ok := args.Data.ContentType().Get(); ok && t == ndn.ContentTypeKey {
			certDataExpired = CertIsExpired(args.Data)
		}
		if !args.certExpiryHandled &&
			(args.crossSchemaExpired || certDataExpired || CertIsExpired(args.cert)) {
			runCertExpiryPolicy(args.OnCertExpired, ndn.CertExpiredCallbackArgs{
				Data:    args.Data,
				RawData: args.RawData,
				Cert:    args.cert,
			}, func(err error) {
				if err != nil {
					args.Callback(false, err)
					return
				}
				args.certExpiryHandled = true
				args.depth++ // Resume the current validation depth.
				tc.Validate(args)
			})
			return
		}

		// Check schema if the key is allowed
		if args.crossSchemaIsValid {
			// continue
		} else if tc.schema.Check(dataName, certName) {
			// continue
		} else if args.Data.CrossSchema() != nil {
			tc.validateCrossSchema(TrustConfigValidateArgs{
				Data:       args.Data,
				RawData:    args.RawData,
				DataSigCov: args.DataSigCov,

				Fetch: args.Fetch,
				Callback: func(valid bool, err error) {
					if valid && err == nil {
						// Continue validation with cross schema
						args.crossSchemaIsValid = true
						tc.Validate(args)
					} else {
						args.Callback(valid, fmt.Errorf("cross schema: %w", err))
					}
				},
				OverrideName:  args.OverrideName,
				OnCertExpired: args.OnCertExpired,
				cert:          args.cert,
				depth:         args.depth,
			})
			return
		} else {
			args.Callback(false, fmt.Errorf("trust schema mismatch: %s signed by %s", dataName, certName))
			return
		}

		// Validate signature on data
		valid, err := signer.ValidateData(args.Data, args.DataSigCov, args.cert)
		if !valid {
			args.Callback(false, fmt.Errorf("signature is invalid"))
			return
		}
		if err != nil {
			args.Callback(false, fmt.Errorf("signature validate error: %w", err))
			return
		}

		// Check if the certificate was already validated.
		// Since all roots are in cache, this breaks the recursion.
		if args.certIsValid {
			args.Callback(true, nil)
			return
		}

		// This should never happen, but just in case
		if len(args.certSigCov) == 0 {
			args.Callback(false, fmt.Errorf("cert sig covered is nil: %s", certName))
			return
		}

		// Monkey patch the callback to store the cert after validation passes.
		origCallback := args.Callback
		args.Callback = func(valid bool, err error) {
			if valid && err == nil {
				// Cache the certificate and the wire needed to revalidate its chain.
				tc.certCache.put(args.cert, args.certSigCov, args.certWire)
				tc.storeCertIfMissing(args.cert, args.certWire)
			} else {
				log.Warn(tc, "Received invalid certificate", "name", args.cert.Name(), "err", err)
			}

			origCallback(valid, err) // continue bubbling up result
		}

		// Recursively validate the certificate
		tc.Validate(TrustConfigValidateArgs{
			Data:       args.cert,
			RawData:    args.certWire,
			DataSigCov: args.certSigCov,

			Fetch:         args.Fetch,
			Callback:      args.Callback,
			OverrideName:  nil,
			OnCertExpired: args.OnCertExpired,
			origDataName:  args.origDataName,

			cert:        nil,
			certSigCov:  nil,
			certWire:    nil,
			certIsValid: false,

			crossSchemaIsValid: false,

			depth: args.depth,
		})
		return
	}

	// Handle self-signed certificate (potential trust anchor).
	if keyLocator.IsPrefix(args.Data.Name()) {
		tc.handleSelfSignedCert(args, keyLocator)
		return
	}

	// Reset all cert fields, this is just for extra safety
	// The code below might seem to have a lot of redundancy - this is intentional.
	args.cert = nil
	args.certSigCov = nil
	args.certWire = nil
	args.certIsValid = false
	args.certExpiryHandled = false
	args.crossSchemaIsValid = false

	// A cache hit supplies evidence, not a reusable validation result. Only an
	// exact trust anchor terminates the chain; every other chain is revalidated.
	if cached, ok := tc.certCache.get(keyLocator); ok &&
		(tc.isTrustAnchor(cached.data.Name()) || len(cached.sigCovered) > 0) {
		args.cert = cached.data
		args.certSigCov = cached.sigCovered
		args.certWire = cached.rawData
		args.certIsValid = tc.isTrustAnchor(cached.data.Name())

		// Continue validation with cached cert
		tc.Validate(args)
		return
	}

	// Attach forwarding hint if needed
	var fwHint []enc.Name = nil
	if args.UseDataNameFwHint.GetOr(tc.UseDataNameFwHint) {
		fwHint = []enc.Name{args.origDataName}
	}

	// Cert not found, attempt to fetch from network
	fetchCfg := &ndn.InterestConfig{
		CanBePrefix:    true,
		MustBeFresh:    true,
		ForwardingHint: fwHint,
	}
	triedLocal := false
	var cb ndn.ExpressCallbackFunc
	cb = func(res ndn.ExpressCallbackArgs) {
		if res.Error == nil && res.Result != ndn.InterestResultData {
			res.Error = fmt.Errorf("failed to fetch certificate (%s) with result: %s", keyLocator, res.Result)
		}

		if res.Error != nil {
			args.Callback(false, res.Error)
			return // failed to fetch cert
		}

		// Bail if not a certificate
		if t, ok := res.Data.ContentType().Get(); !ok || t != ndn.ContentTypeKey {
			if res.IsLocal && !triedLocal {
				triedLocal = true
				if res.Data != nil {
					_ = tc.keychain.Store().Remove(res.Data.Name())
				}
				args.Fetch(keyLocator, fetchCfg, cb)
				return
			}
			args.Callback(false, fmt.Errorf("non-certificate in chain: %s", res.Data.Name()))
			return
		}

		// The certificate's expiry policy is checked when it is used below.
		log.Debug(tc, "Fetched certificate from network", "cert", res.Data.Name())

		// Call again with the fetched cert
		args.cert = res.Data
		args.certSigCov = res.SigCovered
		args.certWire = res.RawData
		args.certIsValid = tc.isTrustAnchor(res.Data.Name())

		// Continue validation with fetched cert
		tc.Validate(args)
	}
	args.Fetch(keyLocator, fetchCfg, cb)
}

// (AI GENERATED DESCRIPTION): Validates the cross‑schema signed Data packet by parsing its embedded schema, checking its validity period, ensuring it authorizes the original certificate, and recursively validating the cross‑schema’s signature against the trust configuration.
func (tc *TrustConfig) validateCrossSchema(args TrustConfigValidateArgs) {
	crossWire := args.Data.CrossSchema()
	if crossWire == nil {
		panic("cross schema is nil")
	}

	// Parse the cross schema data
	crossData, crossDataSigCov, err := spec.Spec{}.ReadData(enc.NewWireView(crossWire))
	if err != nil {
		args.Callback(false, fmt.Errorf("failed to parse cross schema wire: %w", err))
		return
	}

	// Check validity period of the cross schema.
	if CertIsExpired(crossData) {
		runCertExpiryPolicy(args.OnCertExpired, ndn.CertExpiredCallbackArgs{
			Data:    args.Data,
			RawData: args.RawData,
			Cert:    crossData,
		}, func(err error) {
			if err != nil {
				args.Callback(false, err)
				return
			}
			tc.validateCrossSchemaData(args, crossData, crossWire, crossDataSigCov, true)
		})
		return
	}
	tc.validateCrossSchemaData(args, crossData, crossWire, crossDataSigCov, false)
}

func (tc *TrustConfig) validateCrossSchemaData(
	args TrustConfigValidateArgs,
	crossData ndn.Data,
	crossDataRaw enc.Wire,
	crossDataSigCov enc.Wire,
	crossSchemaExpired bool,
) {
	// Parse the cross schema content
	cross, err := trust_schema.ParseCrossSchemaContent(enc.NewWireView(crossData.Content()), false)
	if err != nil {
		args.Callback(false, fmt.Errorf("failed to parse cross schema: %w", err))
		return
	}

	// Check if cross schema authorizes the certificate
	certName := args.cert.Name()
	dataName := args.Data.Name()
	if len(args.OverrideName) > 0 {
		dataName = args.OverrideName
	}
	if !cross.Match(dataName, certName) {
		args.Callback(false, fmt.Errorf("cross schema mismatch: %s signed by %s", dataName, certName))
		return
	}

	// Validate the cross schema signer to sign the original data
	tc.Validate(TrustConfigValidateArgs{
		Data:       crossData,
		RawData:    crossDataRaw,
		DataSigCov: crossDataSigCov,

		Fetch:              args.Fetch,
		Callback:           args.Callback,
		OverrideName:       dataName, // original data
		OnCertExpired:      args.OnCertExpired,
		crossSchemaExpired: crossSchemaExpired,

		depth: args.depth,
	})
}

func (tc *TrustConfig) handleSelfSignedCert(args TrustConfigValidateArgs, keyLocator enc.Name) {
	certDataExpired := false
	if t, ok := args.Data.ContentType().Get(); ok && t == ndn.ContentTypeKey && CertIsExpired(args.Data) {
		certDataExpired = true
	}
	if !args.certExpiryHandled && (args.crossSchemaExpired || certDataExpired) {
		runCertExpiryPolicy(args.OnCertExpired, ndn.CertExpiredCallbackArgs{
			Data:    args.Data,
			RawData: args.RawData,
			Cert:    args.Data,
		}, func(err error) {
			if err != nil {
				args.Callback(false, err)
				return
			}
			args.certExpiryHandled = true
			args.depth++ // Resume the current validation depth.
			tc.Validate(args)
		})
		return
	}

	if len(args.DataSigCov) == 0 {
		args.Callback(false, fmt.Errorf("cert sig covered is nil: %s", args.Data.Name()))
		return
	}

	valid, err := signer.ValidateData(args.Data, args.DataSigCov, args.Data)
	if !valid {
		args.Callback(false, fmt.Errorf("signature is invalid"))
		return
	}
	if err != nil {
		args.Callback(false, fmt.Errorf("signature validate error: %w", err))
		return
	}

	anchorKeyName, err := KeyNameFromLocator(keyLocator)
	if err != nil {
		args.Callback(false, fmt.Errorf("invalid anchor key locator: %w", err))
		return
	}

	// If already a trust anchor
	if tc.isTrustedAnchorKey(anchorKeyName) {
		args.Callback(true, nil)
		return
	}

	// Otherwise, continue validation through a CertList
	tc.exploreCertList(certListArgs{
		args:         args,
		anchorCert:   args.Data,
		anchorRaw:    args.RawData,
		anchorKey:    anchorKeyName,
		visitedLists: map[string]struct{}{},
		visitedCerts: map[string]struct{}{},
	}, anchorKeyName.Append(enc.NewKeywordComponent("auth")))
}

// PromoteAnchor installs a validated trust anchor into caches and keychain.
func (tc *TrustConfig) PromoteAnchor(cert ndn.Data, raw enc.Wire) {
	if cert == nil {
		return
	}
	tc.certCache.put(cert, nil, raw)
	name := cert.Name()
	tc.storeCertIfMissing(cert, raw)

	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	for _, root := range tc.roots {
		if root.Equal(name) {
			return
		}
	}
	tc.roots = append(tc.roots, name)
}

// storeCertIfMissing persists a certificate without inserting it twice.
func (tc *TrustConfig) storeCertIfMissing(cert ndn.Data, wire enc.Wire) {
	if cert == nil || len(wire) == 0 {
		return
	}

	tc.mutex.Lock()
	stored, err := tc.keychain.Store().Get(cert.Name(), false)
	if err == nil && len(stored) == 0 {
		err = tc.keychain.InsertCert(wire.Join())
	}
	tc.mutex.Unlock()
	if err != nil {
		log.Error(tc, "Failed to store certificate", "name", cert.Name(), "err", err)
	}
}

func (tc *TrustConfig) isTrustedAnchorKey(keyLocator enc.Name) bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	keyName, err := KeyNameFromLocator(keyLocator)
	if err != nil {
		return false
	}
	for _, root := range tc.roots {
		if keyName.IsPrefix(root) {
			return true
		}
	}
	return false
}

func (tc *TrustConfig) isTrustAnchor(name enc.Name) bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	for _, root := range tc.roots {
		if root.Equal(name) {
			return true
		}
	}
	return false
}

type certListArgs struct {
	args         TrustConfigValidateArgs
	anchorCert   ndn.Data
	anchorRaw    enc.Wire
	anchorKey    enc.Name
	listData     ndn.Data
	listRaw      enc.Wire
	visitedLists map[string]struct{}
	visitedCerts map[string]struct{}
}

func (tc *TrustConfig) exploreCertList(args certListArgs, prefix enc.Name) {
	key := prefix.TlvStr()
	if _, ok := args.visitedLists[key]; ok {
		args.args.Callback(false, fmt.Errorf("certlist loop"))
		return
	}
	args.visitedLists[key] = struct{}{}

	if cached, ok := tc.certListCache.get(prefix); ok {
		tc.processCertList(args, cached.data, nil, cached.rawData)
		return
	}

	var fwHint []enc.Name
	if args.args.UseDataNameFwHint.GetOr(tc.UseDataNameFwHint) && len(args.args.origDataName) > 0 {
		fwHint = []enc.Name{args.args.origDataName}
	}

	args.args.Fetch(prefix, &ndn.InterestConfig{
		CanBePrefix:    true,
		MustBeFresh:    true,
		ForwardingHint: fwHint,
	}, func(res ndn.ExpressCallbackArgs) {
		if res.Error == nil && res.Result != ndn.InterestResultData {
			res.Error = fmt.Errorf("failed to fetch CertList (%s) with result: %s", prefix, res.Result)
		}

		if res.Error != nil {
			args.args.Callback(false, res.Error)
			return
		}

		tc.processCertList(
			args,
			res.Data,
			res.SigCovered,
			res.RawData,
		)
	})
}

func (tc *TrustConfig) processCertList(
	args certListArgs,
	listData ndn.Data,
	listSigCov enc.Wire,
	listRaw enc.Wire,
) {
	if listData == nil {
		args.args.Callback(false, fmt.Errorf("certlist missing"))
		return
	}
	if !CertListNameMatches(args.anchorKey, listData.Name()) {
		args.args.Callback(false, fmt.Errorf("certlist invalid"))
		return
	}
	if listSigCov != nil {
		valid, err := signer.ValidateData(listData, listSigCov, args.anchorCert)
		if !valid || err != nil {
			args.args.Callback(false, fmt.Errorf("certlist invalid"))
			return
		}
		tc.certListCache.put(args.anchorKey, listData, listRaw)
	}

	names, err := DecodeCertList(listData.Content())
	if err != nil {
		args.args.Callback(false, fmt.Errorf("certlist invalid: %w", err))
		return
	}
	if len(listRaw) > 0 {
		tc.mutex.Lock()
		stored, err := tc.keychain.Store().Get(listData.Name(), false)
		if err == nil && len(stored) == 0 {
			err = tc.keychain.Store().Put(listData.Name(), listRaw.Join())
		}
		tc.mutex.Unlock()
		if err != nil {
			log.Warn(tc, "Failed to store CertList", "name", listData.Name(), "err", err)
		}
	}
	args.listData = listData
	args.listRaw = listRaw
	tc.tryListedCerts(args, names, 0)
}

func (tc *TrustConfig) tryListedCerts(args certListArgs, names []enc.Name, idx int) {
	if idx >= len(names) {
		args.args.Callback(false, fmt.Errorf("no chain to trusted anchor %s (tried %d certs from CertList)", args.anchorKey, len(names)))
		return
	}

	name := names[idx]
	if !args.anchorKey.IsPrefix(name) {
		log.Debug(tc, "redirected cert name mismatch", "anchor", args.anchorKey, "redirect", name)
		tc.tryListedCerts(args, names, idx+1)
		return
	}
	if _, ok := args.visitedCerts[name.TlvStr()]; ok {
		tc.tryListedCerts(args, names, idx+1)
		return
	}
	args.visitedCerts[name.TlvStr()] = struct{}{}

	if cached, ok := tc.certCache.get(name); ok &&
		(tc.isTrustAnchor(cached.data.Name()) || len(cached.sigCovered) > 0) {
		tc.validateListedCert(args, names, idx, cached.data, cached.sigCovered, cached.rawData)
		return
	}

	var fwHint []enc.Name
	if args.args.UseDataNameFwHint.GetOr(tc.UseDataNameFwHint) && len(args.args.origDataName) > 0 {
		fwHint = []enc.Name{args.args.origDataName}
	}

	args.args.Fetch(name, &ndn.InterestConfig{
		CanBePrefix:    true,
		MustBeFresh:    true,
		ForwardingHint: fwHint,
	}, func(res ndn.ExpressCallbackArgs) {
		if res.Error == nil && res.Result != ndn.InterestResultData {
			res.Error = fmt.Errorf("failed to fetch certificate (%s) with result: %s", name, res.Result)
		}

		if res.Error != nil {
			tc.tryListedCerts(args, names, idx+1)
			return
		}

		tc.validateListedCert(args, names, idx, res.Data, res.SigCovered, res.RawData)
	})
}

func (tc *TrustConfig) validateListedCert(
	args certListArgs,
	names []enc.Name,
	idx int,
	cert ndn.Data,
	certSigCov enc.Wire,
	certWire enc.Wire,
) {
	next := func() {
		tc.tryListedCerts(args, names, idx+1)
	}
	if t, ok := cert.ContentType().Get(); !ok || t != ndn.ContentTypeKey {
		next()
		return
	}
	if !bytes.Equal(cert.Content().Join(), args.anchorCert.Content().Join()) {
		next()
		return
	}
	if tc.isTrustAnchor(cert.Name()) {
		tc.validateCertListSigner(args, cert, func() {
			tc.PromoteAnchor(args.anchorCert, args.anchorRaw)
			args.args.Callback(true, nil)
		}, next)
		return
	}

	tc.validateCertListSigner(args, cert, func() {
		tc.Validate(TrustConfigValidateArgs{
			Data:       cert,
			RawData:    certWire,
			DataSigCov: certSigCov,

			Fetch:             args.args.Fetch,
			UseDataNameFwHint: args.args.UseDataNameFwHint,
			Callback: func(valid bool, err error) {
				if valid && err == nil {
					tc.certCache.put(cert, certSigCov, certWire)
					tc.storeCertIfMissing(cert, certWire)
					tc.PromoteAnchor(args.anchorCert, args.anchorRaw)
					args.args.Callback(true, nil)
					return
				}
				next()
			},
			OnCertExpired: args.args.OnCertExpired,
			origDataName:  args.args.origDataName,
			depth:         args.args.depth,
		})
	}, next)
}

// validateCertListSigner applies the expiry policy to the CertList and the
// listed certificate that authenticates its signing key. Their key content was
// checked for equality before this function is called.
func (tc *TrustConfig) validateCertListSigner(args certListArgs, cert ndn.Data, onAccept, onReject func()) {
	if !CertIsExpired(cert) {
		onAccept()
		return
	}

	runCertExpiryPolicy(args.args.OnCertExpired, ndn.CertExpiredCallbackArgs{
		Data:    args.listData,
		RawData: args.listRaw,
		Cert:    cert,
	}, func(err error) {
		if err != nil {
			onReject()
			return
		}
		onAccept()
	})
}

// Returns true if signature time is within certificate validity period
func ValidateSigTime(data ndn.Data, cert ndn.Data) bool {
	if cert.Signature() == nil {
		return false
	}

	sigTime := data.Signature().SigTime()

	if sigTime == nil {
		return false
	}

	notBefore, notAfter := cert.Signature().Validity()
	if val, ok := notBefore.Get(); !ok || sigTime.Before(val) {
		return false
	}
	if val, ok := notAfter.Get(); !ok || sigTime.After(val) {
		return false
	}

	return true
}
