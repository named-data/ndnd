package nac

import (
	"encoding/hex"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

// KeyServer serves NAC keys over NDN.
//
// It exposes:
//   - KEK publicly at <access-prefix>/NAC/<dataset>/KEK/<key-id>
//   - Encrypted KDKs at <access-prefix>/NAC/<dataset>/KDK/<key-id>/ENCRYPTED-BY/<member>
//   - Enrollment at <access-prefix>/NAC/<dataset>/ENROLL
//
// The key server wraps an AccessManager and attaches NDN Interest handlers.
type KeyServer struct {
	engine ndn.Engine
	signer ndn.Signer
	am     *AccessManager

	nacPrefix enc.Name // <access-prefix>/NAC/<dataset>

	// issuedCerts maps key name prefix to certificate Data.
	// Used to verify enrollment request signatures.
	issuedCerts map[string]ndn.Data
}

// NewKeyServer creates a NAC key server for <accessPrefix>/NAC/<dataset>.
func NewKeyServer(engine ndn.Engine, signer ndn.Signer, accessPrefix, dataset string) (*KeyServer, error) {
	am, err := NewAccessManager(accessPrefix, dataset)
	if err != nil {
		return nil, fmt.Errorf("failed to create access manager: %w", err)
	}

	nacPrefixStr := accessPrefix + "/NAC/" + dataset
	prefix, err := enc.NameFromStr(nacPrefixStr)
	if err != nil {
		return nil, fmt.Errorf("invalid NAC prefix: %w", err)
	}

	return &KeyServer{
		engine:      engine,
		signer:      signer,
		am:          am,
		nacPrefix:   prefix,
		issuedCerts: make(map[string]ndn.Data),
	}, nil
}

// AccessManager returns the underlying access manager.
func (ks *KeyServer) AccessManager() *AccessManager {
	return ks.am
}

// RegisterCACert registers a CA certificate as a trust anchor for verifying
// enrollment requests. Client certificates must be signed by one of these CAs.
// The cert is indexed by its key name (cert name minus issuer and version).
func (ks *KeyServer) RegisterCACert(cert ndn.Data) {
	// Store by the key name (cert name minus issuer + version)
	// e.g., /demo/KEY/<id> from /demo/KEY/<id>/NA/v=...
	keyName := cert.Name()
	if len(keyName) >= 2 {
		keyName = keyName[:len(keyName)-2]
	}
	ks.issuedCerts[keyName.String()] = cert
	fmt.Printf("NAC KeyServer: registered CA cert: %s\n", keyName)
}

// Start registers NDN routes and attaches Interest handlers.
func (ks *KeyServer) Start() error {
	if err := ks.engine.RegisterRoute(ks.nacPrefix); err != nil {
		return fmt.Errorf("failed to register route: %w", err)
	}

	kekPrefix := ks.nacPrefix.Append(enc.NewGenericComponent("KEK"))
	if err := ks.engine.AttachHandler(kekPrefix, ks.onKEKInterest); err != nil {
		return fmt.Errorf("failed to attach KEK handler: %w", err)
	}

	kdkPrefix := ks.nacPrefix.Append(enc.NewGenericComponent("KDK"))
	if err := ks.engine.AttachHandler(kdkPrefix, ks.onKDKInterest); err != nil {
		return fmt.Errorf("failed to attach KDK handler: %w", err)
	}

	enrollPrefix := ks.nacPrefix.Append(enc.NewGenericComponent("ENROLL"))
	if err := ks.engine.AttachHandler(enrollPrefix, ks.onEnrollInterest); err != nil {
		return fmt.Errorf("failed to attach ENROLL handler: %w", err)
	}

	fmt.Printf("NAC KeyServer started at %s\n", ks.nacPrefix)
	return nil
}

func (ks *KeyServer) Stop() error {
	ks.engine.DetachHandler(ks.nacPrefix.Append(enc.NewGenericComponent("KEK")))
	ks.engine.DetachHandler(ks.nacPrefix.Append(enc.NewGenericComponent("KDK")))
	ks.engine.DetachHandler(ks.nacPrefix.Append(enc.NewGenericComponent("ENROLL")))
	return nil
}

// onKEKInterest handles Interest for the public KEK.
// Interest name: <access-prefix>/NAC/<dataset>/KEK/<key-id>
func (ks *KeyServer) onKEKInterest(args ndn.InterestHandlerArgs) {
	kek := ks.am.KEK()
	pubKeyBytes := kek.PublicKey.Bytes()

	cfg := &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypeKey),
		Freshness:   optional.Some(time.Hour),
	}

	data, err := ks.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		enc.Wire{pubKeyBytes},
		ks.signer,
	)
	if err != nil {
		fmt.Printf("NAC KeyServer: failed to create KEK response: %v\n", err)
		return
	}

	args.Reply(data.Wire)
}

// onEnrollInterest handles NAC enrollment requests.
//
// The client sends an Interest to <access-prefix>/NAC/<dataset>/ENROLL with AppParam
// containing: [32 bytes X25519 public key] [certificate wire bytes]
//
// The server:
//  1. Splits AppParam into X25519 key (first 32 bytes) and certificate (rest)
//  2. Parses the certificate and verifies it was signed by the CA
//  3. Extracts the consumer identity from the certificate name
//  4. Registers the X25519 key as an authorized NAC member
//
// This ties NDNCERT identity to NAC access: only clients with CA-issued
// certificates can enroll for encrypted content access.
func (ks *KeyServer) onEnrollInterest(args ndn.InterestHandlerArgs) {
	fmt.Printf("NAC ENROLL: handler invoked for %s\n", args.Interest.Name())
	appParam := args.Interest.AppParam()
	if appParam == nil {
		fmt.Println("NAC ENROLL: missing AppParam")
		ks.replyEnrollError(args, "missing AppParam")
		return
	}

	payload := appParam.Join()

	// AppParam format: [32-byte X25519 pubkey][certificate wire]
	if len(payload) < 33 {
		fmt.Println("NAC ENROLL: AppParam too short")
		ks.replyEnrollError(args, "AppParam too short")
		return
	}

	x25519PubBytes := payload[:32]
	certWireBytes := payload[32:]

	// Parse the X25519 public key
	consumerPubKey, err := DeserializePublicKey(x25519PubBytes)
	if err != nil {
		fmt.Printf("NAC ENROLL: invalid X25519 key: %v\n", err)
		ks.replyEnrollError(args, "invalid X25519 public key")
		return
	}

	// Parse the client's certificate
	clientCert, sigCovered, err := spec.Spec{}.ReadData(enc.NewBufferView(certWireBytes))
	if err != nil {
		fmt.Printf("NAC ENROLL: failed to parse certificate: %v\n", err)
		ks.replyEnrollError(args, "invalid certificate")
		return
	}

	fmt.Printf("NAC ENROLL: request from %s\n", clientCert.Name())

	// Verify the certificate was signed by our CA
	// Look up the CA cert that matches the signer key name
	signerKeyName := clientCert.Signature().KeyName()
	caCert, ok := ks.issuedCerts[signerKeyName.String()]
	if !ok {
		fmt.Printf("NAC ENROLL: certificate signer %s not recognized\n", signerKeyName)
		ks.replyEnrollError(args, "certificate not signed by recognized CA")
		return
	}

	valid, err := sig.ValidateData(clientCert, sigCovered, caCert)
	if err != nil || !valid {
		fmt.Printf("NAC ENROLL: certificate verification failed: valid=%v err=%v\n", valid, err)
		ks.replyEnrollError(args, "certificate verification failed")
		return
	}

	// Derive consumer key name from the certificate
	// Certificate name: /demo/emmettlsc.com/KEY/<id>/NDNCERT/v=...
	// Key name (strip issuer + version): /demo/emmettlsc.com/KEY/<id>
	consumerKeyName := clientCert.Name()
	if len(consumerKeyName) >= 2 {
		consumerKeyName = consumerKeyName[:len(consumerKeyName)-2]
	}

	// Add as authorized member
	if err := ks.am.AddMember(consumerKeyName.String(), consumerPubKey); err != nil {
		fmt.Printf("NAC ENROLL: failed to add member: %v\n", err)
		ks.replyEnrollError(args, "enrollment failed")
		return
	}

	fmt.Printf("NAC ENROLL: SUCCESS - enrolled %s (X25519 pub: %s)\n",
		consumerKeyName, hex.EncodeToString(x25519PubBytes))

	// Reply with success + KEK public key so client knows the encryption key
	kek := ks.am.KEK()
	kekPubBytes := kek.PublicKey.Bytes()
	kekIDBytes := kek.ID
	// Response: "OK:" + KEK pub (32 bytes) + KEK ID (16 bytes)
	response := append([]byte("OK:"), kekPubBytes...)
	response = append(response, kekIDBytes...)

	cfg := &ndn.DataConfig{
		Freshness: optional.Some(4 * time.Second),
	}
	data, err := ks.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		enc.Wire{response},
		ks.signer,
	)
	if err != nil {
		fmt.Printf("NAC ENROLL: failed to create response: %v\n", err)
		return
	}
	args.Reply(data.Wire)
}

func (ks *KeyServer) replyEnrollError(args ndn.InterestHandlerArgs, msg string) {
	cfg := &ndn.DataConfig{
		Freshness: optional.Some(4 * time.Second),
	}
	data, err := ks.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		enc.Wire{[]byte("ERR:" + msg)},
		ks.signer,
	)
	if err != nil {
		return
	}
	args.Reply(data.Wire)
}

// onKDKInterest handles Interest for encrypted KDKs.
// Interest name: <access-prefix>/NAC/<dataset>/KDK/<key-id>/ENCRYPTED-BY/<consumer-key-name>
func (ks *KeyServer) onKDKInterest(args ndn.InterestHandlerArgs) {
	name := args.Interest.Name()

	// Parse the consumer key name from the /ENCRYPTED-BY/ component
	nameStr := name.String()
	_, consumerKeyName, err := ParseEncryptedByName(nameStr)
	if err != nil {
		fmt.Printf("NAC KeyServer: invalid KDK Interest name: %s\n", nameStr)
		return
	}

	// Look up the encrypted KDK for this consumer
	encKDK, ok := ks.am.GetEncryptedKDK(consumerKeyName)
	if !ok {
		fmt.Printf("NAC KeyServer: unauthorized consumer: %s\n", consumerKeyName)
		return // Silently drop - unauthorized consumer gets no response
	}

	cfg := &ndn.DataConfig{
		Freshness: optional.Some(time.Hour),
	}

	data, err := ks.engine.Spec().MakeData(
		args.Interest.Name(),
		cfg,
		enc.Wire{encKDK},
		ks.signer,
	)
	if err != nil {
		fmt.Printf("NAC KeyServer: failed to create KDK response: %v\n", err)
		return
	}

	args.Reply(data.Wire)
}
