package nac

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
)

// KeyServer serves NAC keys over NDN.
//
// It exposes:
//   - KEK publicly at <credential-prefix>/E-KEY/<key-id> (any producer can fetch)
//   - Encrypted KDKs at <kdk-name>/FOR/<consumer-key-name> (only authorized consumers)
//
// The key server wraps an AccessManager and attaches NDN Interest handlers.
type KeyServer struct {
	engine ndn.Engine
	signer ndn.Signer
	am     *AccessManager

	credPrefix enc.Name
}

// NewKeyServer creates a NAC key server.
func NewKeyServer(engine ndn.Engine, signer ndn.Signer, credentialPrefix string) (*KeyServer, error) {
	am, err := NewAccessManager(credentialPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create access manager: %w", err)
	}

	prefix, err := enc.NameFromStr(credentialPrefix)
	if err != nil {
		return nil, fmt.Errorf("invalid credential prefix: %w", err)
	}

	return &KeyServer{
		engine:     engine,
		signer:     signer,
		am:         am,
		credPrefix: prefix,
	}, nil
}

// AccessManager returns the underlying access manager.
func (ks *KeyServer) AccessManager() *AccessManager {
	return ks.am
}

// Start registers NDN routes and attaches Interest handlers.
func (ks *KeyServer) Start() error {
	// Register the credential prefix route
	if err := ks.engine.RegisterRoute(ks.credPrefix); err != nil {
		return fmt.Errorf("failed to register route: %w", err)
	}

	// Attach KEK handler: <credential-prefix>/E-KEY
	kekPrefix := ks.credPrefix.Append(enc.NewGenericComponent("E-KEY"))
	if err := ks.engine.AttachHandler(kekPrefix, ks.onKEKInterest); err != nil {
		return fmt.Errorf("failed to attach KEK handler: %w", err)
	}

	// Attach KDK handler: <credential-prefix>/D-KEY
	kdkPrefix := ks.credPrefix.Append(enc.NewGenericComponent("D-KEY"))
	if err := ks.engine.AttachHandler(kdkPrefix, ks.onKDKInterest); err != nil {
		return fmt.Errorf("failed to attach KDK handler: %w", err)
	}

	fmt.Printf("NAC KeyServer started at %s\n", ks.credPrefix)
	return nil
}

// Stop detaches Interest handlers.
func (ks *KeyServer) Stop() error {
	ks.engine.DetachHandler(ks.credPrefix.Append(enc.NewGenericComponent("E-KEY")))
	ks.engine.DetachHandler(ks.credPrefix.Append(enc.NewGenericComponent("D-KEY")))
	return nil
}

// onKEKInterest handles Interest for the public KEK.
// Interest name: <credential-prefix>/E-KEY/<key-id>
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

// onKDKInterest handles Interest for encrypted KDKs.
// Interest name: <credential-prefix>/D-KEY/<key-id>/FOR/<consumer-key-name>
func (ks *KeyServer) onKDKInterest(args ndn.InterestHandlerArgs) {
	name := args.Interest.Name()

	// Parse the consumer key name from the /FOR/ component
	nameStr := name.String()
	_, consumerKeyName, err := ParseEncryptedDataName(nameStr)
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
