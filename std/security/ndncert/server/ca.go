package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	"github.com/named-data/ndnd/std/types/optional"
)

type CaServer struct {
	engine  ndn.Engine
	config  *CaConfig
	storage Storage
	signer  ndn.Signer

	caCertWire enc.Wire
	caPrefix   enc.Name
	caProfile  *tlv.CaProfile
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

	server := &CaServer{
		engine:     engine,
		config:     config,
		storage:    store,
		signer:     signer,
		caCertWire: caCertWire,
		caPrefix:   caPrefix,
		caProfile:  caProfile,
	}

	return server, nil
}

func (ca *CaServer) Start() error {
	if err := ca.engine.RegisterRoute(ca.caPrefix); err != nil {
		return fmt.Errorf("failed to register route: %w", err)
	}

	base := ca.caPrefix.Append(enc.NewGenericComponent("CA"))

	infoPrefix := base.Append(enc.NewGenericComponent("INFO"))
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

	return nil
}

func (ca *CaServer) Stop() error {
	base := ca.caPrefix.Append(enc.NewGenericComponent("CA"))

	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("INFO")))
	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("PROBE")))
	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("NEW")))
	ca.engine.DetachHandler(base.Append(enc.NewGenericComponent("CHALLENGE")))

	return nil
}

// handle INFO
func (ca *CaServer) onInfo(args ndn.InterestHandlerArgs) {
	profileWire := ca.caProfile.Encode()

	cfg := &ndn.DataConfig{
		Freshness: optional.Some(10 * time.Second),
	}

	data, err := ca.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		profileWire,
		ca.signer,
	)
	if err != nil {
		// fmt.Printf("info response err: %v\n", err)
		fmt.Printf("ERROR: Failed to create INFO response: %v\n", err)
		return
	}

	args.Reply(data.Wire)
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
		if ch.Name == ndncert.KwPin {
			selectedChallenge = ch.Name
			break
		}
	}
	if selectedChallenge == "" {
		ca.sendError(args, 7, "no supported challenge available")
		return
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

// challenge handler (todo)
func (ca *CaServer) onChallenge(args ndn.InterestHandlerArgs) {
	ca.sendError(args, 99, "TODO")
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

func deriveEcdhKey(caKey *ecdh.PrivateKey, clientPubKey []byte, salt []byte, requestID []byte) ([16]byte, error) {
	keyBytes, err := ndncert.EcdhHkdf(caKey, clientPubKey, salt, requestID)
	if err != nil {
		return [16]byte{}, err
	}

	var key [16]byte
	copy(key[:], keyBytes)
	return key, nil
}
