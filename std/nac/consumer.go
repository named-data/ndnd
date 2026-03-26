package nac

import (
	"crypto/ecdh"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
)

// Consumer fetches NAC keys over NDN and decrypts content.
type Consumer struct {
	engine          ndn.Engine
	consumerKeyName string
	privateKey      *ecdh.PrivateKey
	decryptor       *Decryptor
}

// NewConsumer creates a NAC consumer that can fetch keys and decrypt content.
func NewConsumer(engine ndn.Engine, consumerKeyName string, privateKey *ecdh.PrivateKey) *Consumer {
	return &Consumer{
		engine:          engine,
		consumerKeyName: consumerKeyName,
		privateKey:      privateKey,
		decryptor:       NewDecryptor(consumerKeyName, privateKey),
	}
}

// FetchKEK fetches the public Key Encryption Key from the network.
// kekName is the full NDN name: <credential-prefix>/E-KEY/<key-id>
func (c *Consumer) FetchKEK(kekName string) (*KeyEncryptionKey, error) {
	name, err := enc.NameFromStr(kekName)
	if err != nil {
		return nil, fmt.Errorf("invalid KEK name: %w", err)
	}

	ch := make(chan ndn.ExpressCallbackArgs, 1)
	interest, err := c.engine.Spec().MakeInterest(name, &ndn.InterestConfig{
		CanBePrefix: true,
		Lifetime:    optional.Some(4 * time.Second),
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make KEK interest: %w", err)
	}

	c.engine.Express(interest, func(args ndn.ExpressCallbackArgs) { ch <- args })
	args := <-ch

	if args.Result != ndn.InterestResultData {
		return nil, fmt.Errorf("failed to fetch KEK: %s", args.Result)
	}

	pubKeyBytes := args.Data.Content().Join()
	pubKey, err := DeserializePublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid KEK public key: %w", err)
	}

	return &KeyEncryptionKey{
		PublicKey: pubKey,
	}, nil
}

// FetchEncryptedKDK fetches the encrypted KDK for this consumer from the network.
// kdkForName is: <kdk-name>/FOR/<consumer-key-name>
func (c *Consumer) FetchEncryptedKDK(kdkForName string) ([]byte, error) {
	name, err := enc.NameFromStr(kdkForName)
	if err != nil {
		return nil, fmt.Errorf("invalid KDK name: %w", err)
	}

	ch := make(chan ndn.ExpressCallbackArgs, 1)
	interest, err := c.engine.Spec().MakeInterest(name, &ndn.InterestConfig{
		CanBePrefix: true,
		Lifetime:    optional.Some(4 * time.Second),
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make KDK interest: %w", err)
	}

	c.engine.Express(interest, func(args ndn.ExpressCallbackArgs) { ch <- args })
	args := <-ch

	if args.Result != ndn.InterestResultData {
		return nil, fmt.Errorf("failed to fetch encrypted KDK: %s", args.Result)
	}

	return args.Data.Content().Join(), nil
}

// Decrypt decrypts content using the full NAC chain, fetching keys from network as needed.
func (c *Consumer) Decrypt(
	encContent *EncryptedContent,
	encCK *EncryptedCK,
	encKDKBlob []byte,
) ([]byte, error) {
	return c.decryptor.Decrypt(encContent, encCK, encKDKBlob)
}
