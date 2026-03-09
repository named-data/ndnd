package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

type CaServer struct {
	engine  ndn.Engine
	config  *CaConfig
	storage Storage
	signer  ndn.Signer

	caCertWire  enc.Wire
	caPrefix    enc.Name
	caProfile   *tlv.CaProfile
	objectStore ndn.Store // RDR store - needed for serving CA profile
	// TODO: remove for final version, DNSResolver is only useful for testing with mock dns records
	// 	if nil then net.LookupTXT is used
	DNSResolver func(domain string) ([]string, error)
}

func NewCaServer(engine ndn.Engine, config *CaConfig, caCertWire enc.Wire, signer ndn.Signer) (*CaServer, error) {
	caPrefix, err := enc.NameFromStr(config.CaPrefix)
	if err != nil {
		return nil, fmt.Errorf("invalid ca-prefix: %w", err)
	}

	caProfile, err := config.ToCaProfile(caCertWire)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA profile: %w", err)
	}

	store := NewMemoryStorage()
	objStore := storage.NewMemoryStore()

	server := &CaServer{
		engine:      engine,
		config:      config,
		storage:     store,
		signer:      signer,
		caCertWire:  caCertWire,
		caPrefix:    caPrefix,
		caProfile:   caProfile,
		objectStore: objStore,
	}

	return server, nil
}

func (ca *CaServer) Start() error {
	if err := ca.engine.RegisterRoute(ca.caPrefix); err != nil {
		return fmt.Errorf("failed to register route: %w", err)
	}

	base := ca.caPrefix.Append(enc.NewGenericComponent("CA"))

	// make CA profile now with RDR metadata
	infoPrefix := base.Append(enc.NewGenericComponent("INFO"))
	version := utils.MakeTimestamp(time.Now())
	infoName := infoPrefix.Append(enc.NewVersionComponent(version))
	profileWire := ca.caProfile.Encode()

	_, err := object.Produce(ndn.ProduceArgs{
		Name:            infoName,
		Content:         profileWire,
		FreshnessPeriod: 10 * time.Second,
		NoMetadata:      false,
	}, ca.objectStore, ca.signer)
	if err != nil {
		return fmt.Errorf("failed to produce CA profile: %w", err)
	}

	if err := ca.engine.AttachHandler(infoPrefix, ca.onInfo); err != nil {
		return fmt.Errorf("failed to attach INFO handler: %w", err)
	}

	probePrefix := base.Append(enc.NewGenericComponent("PROBE"))
	if err := ca.engine.AttachHandler(probePrefix, ca.onProbe); err != nil {
		return fmt.Errorf("failed to attach PROBE handler: %w", err)
	}

	newPrefix := base.Append(enc.NewGenericComponent("NEW"))
	if err := ca.engine.AttachHandler(newPrefix, ca.onNew); err != nil {
		return fmt.Errorf("failed to attach NEW handler: %w", err)
	}

	chPrefix := base.Append(enc.NewGenericComponent("CHALLENGE"))
	if err := ca.engine.AttachHandler(chPrefix, ca.onChallenge); err != nil {
		return fmt.Errorf("failed to attach CHALLENGE handler: %w", err)
	}

	if err := ca.engine.AttachHandler(ca.caPrefix, ca.onObjectFetch); err != nil {
		return fmt.Errorf("failed to attach object fetch handler: %w", err)
	}

	return nil
}

func (ca *CaServer) Stop() error {
	base := ca.caPrefix.Append(enc.NewGenericComponent("CA"))

	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("INFO")))
	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("PROBE")))
	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("NEW")))
	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("CHALLENGE")))
	ca.engine.DetachHandler(ca.caPrefix)
	return nil
}

// handle INFO - serves CA profile using RDR from object store
func (ca *CaServer) onInfo(args ndn.InterestHandlerArgs) {
	data, err := ca.objectStore.Get(args.Interest.Name(), args.Interest.CanBePrefix())
	if err != nil {
		fmt.Printf("ERROR: failed to get INFO from store: %v\n", err)
		return
	}
	if data == nil {
		fmt.Printf("INFO: no data found for %s\n", args.Interest.Name())
		return
	}

	args.Reply(enc.Wire{data})
}

// serves data from object store
func (ca *CaServer) onObjectFetch(args ndn.InterestHandlerArgs) {
	data, err := ca.objectStore.Get(args.Interest.Name(), args.Interest.CanBePrefix())
	if err != nil {
		fmt.Printf("ERROR: failed to get object from store: %v\n", err)
		return
	}
	if data == nil {
		// Not found in store, don't reply (let other handlers try)
		return
	}

	args.Reply(enc.Wire{data})
}

// PPROBE handler
func (ca *CaServer) onProbe(args ndn.InterestHandlerArgs) {
	appParam := args.Interest.AppParam()
	if appParam == nil {
		ca.sendError(args, 1, "missing application parameters")
		return
	}

	probeReq, err := tlv.ParseProbeReq(enc.NewWireView(appParam), false)
	if err != nil {
		ca.sendError(args, 2, fmt.Sprintf("invalid PROBE request: %v", err))
		return
	}

	vals := make([]*tlv.ProbeResVals, 0)

	probeKeys := ca.config.GetProbeParamKeys()
	if len(probeKeys) > 0 {
		firstKey := probeKeys[0]
		if paramValue, ok := probeReq.Params[firstKey]; ok {
			suggestedName := ca.caPrefix.Append(enc.NewGenericComponent(string(paramValue)))
			vals = append(vals, &tlv.ProbeResVals{
				Response:        suggestedName,
				MaxSuffixLength: optional.Some(uint64(2)),
			})
		}
	}

	probeRes := &tlv.ProbeRes{
		Vals:           vals,
		RedirectPrefix: nil,
	}

	cfg := &ndn.DataConfig{
		Freshness: optional.Some(10 * time.Second),
	}

	data, err := ca.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		probeRes.Encode(),
		ca.signer,
	)
	if err != nil {
		fmt.Printf("ERROR: Failed to create PROBE response: %v\n", err)
		return
	}

	args.Reply(data.Wire)
}

// NEW handler
func (ca *CaServer) onNew(args ndn.InterestHandlerArgs) {
	appParam := args.Interest.AppParam()
	if appParam == nil {
		ca.sendError(args, 1, "missing application parameters")
		return
	}

	newReq, err := tlv.ParseNewReq(enc.NewWireView(appParam), false)
	if err != nil {
		ca.sendError(args, 2, fmt.Sprintf("invalid NEW request: %v", err))
		return
	}

	if len(newReq.EcdhPub) == 0 {
		ca.sendError(args, 3, "missing ECDH public key")
		return
	}

	if newReq.CertReq == nil {
		ca.sendError(args, 4, "missing certificate request")
		return
	}

	certReq, _, err := ca.engine.Spec().ReadData(enc.NewWireView(newReq.CertReq))
	if err != nil {
		ca.sendError(args, 5, fmt.Sprintf("invalid certificate request: %v", err))
		return
	}
	fmt.Printf("INFO: received NEW request for identity: %s\n", certReq.Name())

	requestID := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, requestID); err != nil {
		ca.sendError(args, 100, "internal error")
		return
	}

	caEcdhKey, err := ndncert.EcdhKeygen()
	if err != nil {
		ca.sendError(args, 100, "internal error")
		return
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		ca.sendError(args, 100, "internal error")
		return
	}

	aesKeyBytes, err := ndncert.EcdhHkdf(caEcdhKey, newReq.EcdhPub, salt, requestID)
	if err != nil {
		ca.sendError(args, 6, fmt.Sprintf("ECDH key derivation failed: %v", err))
		return
	}

	var aesKey [16]byte
	copy(aesKey[:], aesKeyBytes)

	state := NewRequestState(requestID, ca.caPrefix)
	state.CertRequest = newReq.CertReq
	state.RequestedCertName = certReq.Name()
	state.ClientEcdhPub = newReq.EcdhPub
	state.CaEcdhKey = caEcdhKey
	state.Salt = salt
	state.AesKey = aesKey
	state.AeadCounter = ndncert.NewAeadCounter()
	state.Status = StatusBeforeChallenge

	selectedChallenge := ""
	for _, ch := range ca.config.SupportedChallenges {
		if ch.Name == ndncert.KwDns {
			selectedChallenge = ch.Name
			break
		}
	}

	state.ChallengeType = selectedChallenge

	if err := ca.storage.Put(requestID, state); err != nil {
		ca.sendError(args, 100, "internal error")
		return
	}

	newRes := &tlv.NewRes{
		EcdhPub:   caEcdhKey.PublicKey().Bytes(),
		Salt:      salt,
		ReqId:     requestID,
		Challenge: []string{selectedChallenge},
	}

	cfg := &ndn.DataConfig{
		Freshness: optional.Some(4 * time.Second),
	}

	data, err := ca.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		newRes.Encode(),
		ca.signer,
	)
	if err != nil {
		fmt.Printf("ERROR: Failed to create NEW response: %v\n", err)
		return
	}

	args.Reply(data.Wire)
}

// CHALLENGE handler
func (ca *CaServer) onChallenge(args ndn.InterestHandlerArgs) {
	// fetch request ID from Interest name: /<ca-prefix>/CA/CHALLENGE/<request-id>
	name := args.Interest.Name()
	baseLen := len(ca.caPrefix) + 2 // caPrefix + CA + CHALLENGE
	if len(name) < baseLen+1 {
		ca.sendError(args, 1, "missing request ID in name")
		return
	}

	requestID := name[baseLen].Val
	if len(requestID) == 0 {
		ca.sendError(args, 1, "empty request ID")
		return
	}

	fmt.Printf("INFO: received CHALLENGE request, ID=%x\n", requestID)

	state, err := ca.storage.Get(requestID)
	if err != nil {
		ca.sendError(args, 100, "internal error")
		return
	}
	if state == nil {
		ca.sendError(args, 8, "request not found or expired")
		return
	}

	if state.IsExpired() {
		ca.sendError(args, 9, "request expired")
		return
	}

	// parse and decrypt challenge parameters
	appParam := args.Interest.AppParam()
	if appParam == nil {
		ca.sendError(args, 1, "missing application parameters")
		return
	}

	params, err := ca.decryptChallengeParams(appParam, state)
	if err != nil {
		ca.sendError(args, 10, fmt.Sprintf("failed to decrypt parameters: %v", err))
		return
	}

	// route to the rigt challenge handler
	var responseParams ndncert.ParamMap
	var challengeStatus string
	var challengeErr error

	fmt.Printf("INFO: processing %s challenge, status=%d\n", state.ChallengeType, state.Status)

	switch state.ChallengeType {
	case ndncert.KwDns:
		handler := &ChallengeDnsHandler{
			DNSResolver: ca.DNSResolver,
		}
		responseParams, challengeStatus, challengeErr = handler.HandleChallenge(params, state)
		fmt.Printf("INFO: DNS challenge result: status=%s, success=%v\n", challengeStatus, state.Status == StatusSuccess)

	default:
		ca.sendError(args, 11, fmt.Sprintf("unsupported challenge type: %s", state.ChallengeType))
		return
	}

	// challenge errors
	if challengeErr != nil {
		ca.sendError(args, 12, fmt.Sprintf("challenge error: %v", challengeErr))
		return
	}

	// update request state
	if err := ca.storage.Put(requestID, state); err != nil {
		ca.sendError(args, 100, "internal error")
		return
	}

	// build and send response based on challenge outcome
	if state.Status == StatusSuccess {
		fmt.Printf("INFO: challenge completed successfully, issuing cert\n")
		cert, err := ca.issueCertificate(state)
		if err != nil {
			ca.sendError(args, 13, fmt.Sprintf("failed to issue certificate: %v", err))
			return
		}

		// parse cert to get its name
		certData, _, err := ca.engine.Spec().ReadData(enc.NewWireView(cert))
		if err != nil {
			ca.sendError(args, 15, fmt.Sprintf("failed to parse issued certificate: %v", err))
			return
		}
		certName := certData.Name()

		// store certificate in mem for client to fetch
		err = ca.objectStore.Put(certName, cert.Join())
		if err != nil {
			ca.sendError(args, 16, fmt.Sprintf("failed to store certificate: %v", err))
			return
		}

		fmt.Printf("INFO: Certificate issued and stored: %s\n", certName)

		state.MarkSuccess(cert)
		ca.storage.Put(requestID, state)

		//ret success response w/ cert name
		chRes := &tlv.ChallengeRes{
			Status:         StatusSuccess,
			ChalStatus:     optional.Some(challengeStatus),
			CertName:       &spec.NameContainer{Name: certName},
			ForwardingHint: nil,
			Params:         responseParams,
			RemainTries:    optional.None[uint64](),
			RemainTime:     optional.None[uint64](),
		}

		encryptedResponse, err := ca.encryptChallengeResponse(chRes, state)
		if err != nil {
			ca.sendError(args, 14, fmt.Sprintf("failed to encrypt response: %v", err))
			return
		}

		cfg := &ndn.DataConfig{
			Freshness: optional.Some(4 * time.Second),
		}

		data, err := ca.engine.Spec().MakeData(
			args.Interest.Name(),
			cfg,
			encryptedResponse,
			ca.signer,
		)
		if err != nil {
			fmt.Printf("ERROR: failed to create CHALLENGE response: %v\n", err)
			return
		}

		args.Reply(data.Wire)
		return
	}

	// challenge still in progress -> build complete ChallengeRes and encrypt it
	chRes := &tlv.ChallengeRes{
		Status:         state.Status,
		ChalStatus:     optional.Some(challengeStatus),
		RemainTries:    optional.Some(uint64(state.RemainingAttempts())),
		RemainTime:     optional.None[uint64](),
		CertName:       nil,
		ForwardingHint: nil,
		Params:         responseParams,
	}

	encryptedResponse, err := ca.encryptChallengeResponse(chRes, state)
	if err != nil {
		ca.sendError(args, 14, fmt.Sprintf("failed to encrypt response: %v", err))
		return
	}

	cfg := &ndn.DataConfig{
		Freshness: optional.Some(4 * time.Second),
	}

	// response content is the encrypted ChallengeRes (as CipherMsg)
	data, err := ca.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		encryptedResponse,
		ca.signer,
	)
	if err != nil {
		fmt.Printf("ERROR: failed to create CHALLENGE response: %v\n", err)
		return
	}

	args.Reply(data.Wire)
}

// issueCertificate signs and issues a certificate for the given request
func (ca *CaServer) issueCertificate(state *RequestState) (enc.Wire, error) {
	// parse the cert request from state
	certReqData, _, err := ca.engine.Spec().ReadData(enc.NewWireView(state.CertRequest))
	if err != nil {
		return enc.Wire{}, fmt.Errorf("failed to parse certificate request: %w", err)
	}
	maxValiditySec, err := ca.config.GetMaxValidityPeriodSeconds()
	if err != nil {
		return enc.Wire{}, fmt.Errorf("invalid max validity period: %w", err)
	}

	// issue the certificate
	now := time.Now()
	notBefore := now
	notAfter := now.Add(time.Duration(maxValiditySec) * time.Second)

	certWire, err := security.SignCert(security.SignCertArgs{
		Signer:    ca.signer,
		Data:      certReqData,
		IssuerId:  enc.NewGenericComponent("NDNCERT"),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
	if err != nil {
		return enc.Wire{}, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return certWire, nil
}

func (ca *CaServer) sendError(args ndn.InterestHandlerArgs, code uint64, info string) {
	errRes := &tlv.ErrorRes{
		ErrCode: code,
		ErrInfo: info,
	}

	cfg := &ndn.DataConfig{
		Freshness: optional.Some(4 * time.Second),
	}

	data, err := ca.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		errRes.Encode(),
		ca.signer,
	)
	if err != nil {
		fmt.Printf("ERROR: Failed to create error response: %v\n", err)
		return
	}

	args.Reply(data.Wire)
}

// decryptChallengeParams decrypts CHALLENGE request parameters using AEAD
func (ca *CaServer) decryptChallengeParams(encParams enc.Wire, state *RequestState) (ndncert.ParamMap, error) {
	cipherMsg, err := tlv.ParseCipherMsg(enc.NewWireView(encParams), false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cipher message: %w", err)
	}

	var aeadMsg ndncert.AeadMessage
	aeadMsg.FromTLV(cipherMsg)
	// decrypt w/ request ID as additional data
	plaintext, err := ndncert.AeadDecrypt(state.AesKey, aeadMsg, state.RequestID)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// parse decrypted ChallengeReq
	chReq, err := tlv.ParseChallengeReq(enc.NewWireView(enc.Wire{plaintext}), false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse challenge request: %w", err)
	}

	return chReq.Params, nil
}

// encryptChallengeResponse encrypts a full ChallengeRes structure using AEAD
func (ca *CaServer) encryptChallengeResponse(chRes *tlv.ChallengeRes, state *RequestState) (enc.Wire, error) {
	plaintext := chRes.Encode()

	// encrypt w/ request ID as additional data
	aeadMsg, err := ndncert.AeadEncrypt(state.AesKey, plaintext.Join(), state.RequestID, state.AeadCounter)
	if err != nil {
		return enc.Wire{}, fmt.Errorf("failed to encrypt: %w", err)
	}

	return aeadMsg.TLV().Encode(), nil
}

func deriveEcdhKey(caKey *ecdh.PrivateKey, clientPubKey []byte, salt []byte, requestID []byte) ([16]byte, error) {
	keyBytes, err := ndncert.EcdhHkdf(caKey, clientPubKey, salt, requestID)
	if err != nil {
		return [16]byte{}, err
	}

	var key [16]byte
	copy(key[:], keyBytes)
	return key, nil
}
