package tools

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/nac"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/spf13/cobra"
)

type NacServer struct {
	flags struct {
		members []string
	}
}

// CmdNac creates the nac command group
func CmdNac() *cobra.Command {
	cmd := &cobra.Command{
		GroupID: "tools",
		Use:     "nac",
		Short:   "Name-based Access Control (NAC) tools",
	}

	ns := NacServer{}
	serveCmd := &cobra.Command{
		Use:   "serve CREDENTIAL-PREFIX",
		Short: "Run NAC key server",
		Long: `Run the NAC key server that serves KEK (public) and encrypted KDKs (per-consumer).

Members are specified as consumer-key-name:hex-public-key pairs.
The key server serves:
  - KEK at <credential-prefix>/E-KEY/<key-id>  (public, any producer can fetch)
  - KDK at <credential-prefix>/D-KEY/<key-id>/FOR/<consumer>  (authorized consumers only)`,
		Args:    cobra.ExactArgs(1),
		Run:     ns.runServe,
		Example: `  ndnd nac serve /alice/read/documents --member "/alice/KEY/abc123:0a1b2c..."`,
	}
	serveCmd.Flags().StringArrayVar(&ns.flags.members, "member", nil, "Authorized member as 'consumer-key-name:hex-x25519-pubkey'")
	cmd.AddCommand(serveCmd)

	cmd.AddCommand(cmdNacEncrypt())
	cmd.AddCommand(cmdNacDecrypt())

	return cmd
}

func (ns *NacServer) String() string {
	return "nac-server"
}

func (ns *NacServer) runServe(_ *cobra.Command, args []string) {
	credPrefix := args[0]

	// ctart NDN engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	if err := app.Start(); err != nil {
		log.Fatal(ns, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// create a signer for signing Data packets
	keyName, _ := enc.NameFromStr(credPrefix + "/KEY/nac-server")
	signer, err := sig.KeygenEd25519(keyName)
	if err != nil {
		log.Fatal(ns, "Unable to generate signing key", "err", err)
		return
	}

	// create key server
	ks, err := nac.NewKeyServer(app, signer, credPrefix)
	if err != nil {
		log.Fatal(ns, "Unable to create key server", "err", err)
		return
	}

	// add members
	for _, memberSpec := range ns.flags.members {
		consumerKeyName, pubKey, err := parseMemberSpec(memberSpec)
		if err != nil {
			log.Fatal(ns, "Invalid member spec", "spec", memberSpec, "err", err)
			return
		}
		if err := ks.AccessManager().AddMember(consumerKeyName, pubKey); err != nil {
			log.Fatal(ns, "Failed to add member", "member", consumerKeyName, "err", err)
			return
		}
		fmt.Printf("Added authorized member: %s\n", consumerKeyName)
	}

	kek := ks.AccessManager().KEK()
	fmt.Printf("KEK ID: %s\n", hex.EncodeToString(kek.ID))
	fmt.Printf("KEK Name: %s\n", nac.KEKName(credPrefix, kek.ID))

	// start serving keys
	if err := ks.Start(); err != nil {
		log.Fatal(ns, "Unable to start key server", "err", err)
		return
	}
	defer ks.Stop()

	// wait for signal
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	<-sigchan
	log.Info(nil, "Shutting down NAC key server")
}

func parseMemberSpec(spec string) (string, *ecdh.PublicKey, error) {
	// format: consumer-key-name:hex-x25519-pubkey
	for i := len(spec) - 1; i >= 0; i-- {
		if spec[i] == ':' {
			keyName := spec[:i]
			pubKeyHex := spec[i+1:]

			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil {
				return "", nil, fmt.Errorf("invalid hex public key: %w", err)
			}

			pubKey, err := nac.DeserializePublicKey(pubKeyBytes)
			if err != nil {
				return "", nil, fmt.Errorf("invalid X25519 public key: %w", err)
			}

			return keyName, pubKey, nil
		}
	}
	return "", nil, fmt.Errorf("expected format 'consumer-key-name:hex-x25519-pubkey'")
}

func cmdNacEncrypt() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt KEK-PUB-HEX CREDENTIAL-PREFIX DATA-PREFIX",
		Short: "Encrypt stdin with NAC",
		Long: `Encrypt data from stdin using NAC.
Outputs encrypted content, encrypted CK, and CK name to files.`,
		Args: cobra.ExactArgs(3),
		Run:  runNacEncrypt,
	}
}

func runNacEncrypt(_ *cobra.Command, args []string) {
	pubKeyHex := args[0]
	credPrefix := args[1]
	dataPrefix := args[2]

	// parse KEK public key
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		log.Fatal(nil, "Invalid KEK hex", "err", err)
		return
	}
	pubKey, err := nac.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		log.Fatal(nil, "Invalid X25519 public key", "err", err)
		return
	}

	kek := &nac.KeyEncryptionKey{PublicKey: pubKey}
	encryptor := nac.NewEncryptor(dataPrefix, credPrefix, kek)

	// read plaintext from stdin
	plaintext, err := os.ReadFile("/dev/stdin")
	if err != nil {
		log.Fatal(nil, "Failed to read stdin", "err", err)
		return
	}

	contentName := dataPrefix + "/data"
	encContent, encCK, err := encryptor.Encrypt(contentName, plaintext)
	if err != nil {
		log.Fatal(nil, "Encryption failed", "err", err)
		return
	}

	// write encrypted content
	if err := os.WriteFile("enc-content.bin", encContent.EncryptedPayload, 0644); err != nil {
		log.Fatal(nil, "Failed to write encrypted content", "err", err)
		return
	}

	// write encrypted CK
	if err := os.WriteFile("enc-ck.bin", encCK.EncryptedPayload, 0644); err != nil {
		log.Fatal(nil, "Failed to write encrypted CK", "err", err)
		return
	}

	fmt.Fprintf(os.Stderr, "Encrypted content: enc-content.bin (%d bytes)\n", len(encContent.EncryptedPayload))
	fmt.Fprintf(os.Stderr, "Encrypted CK: enc-ck.bin (%d bytes)\n", len(encCK.EncryptedPayload))
	fmt.Fprintf(os.Stderr, "Content name: %s\n", encContent.Name)
	fmt.Fprintf(os.Stderr, "CK name: %s\n", encCK.Name)
}

func cmdNacDecrypt() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt PRIVATE-KEY-HEX CONSUMER-KEY-NAME ENC-KDK-FILE ENC-CK-FILE ENC-CONTENT-FILE",
		Short: "Decrypt NAC-encrypted data",
		Long:  `Decrypt NAC-encrypted data using consumer's private key and the encrypted KDK/CK/content files.`,
		Args:  cobra.ExactArgs(5),
		Run:   runNacDecrypt,
	}
}

func runNacDecrypt(_ *cobra.Command, args []string) {
	privKeyHex := args[0]
	consumerKeyName := args[1]
	encKDKFile := args[2]
	encCKFile := args[3]
	encContentFile := args[4]

	// parse private key
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		log.Fatal(nil, "Invalid private key hex", "err", err)
		return
	}
	privKey, err := nac.DeserializePrivateKey(privKeyBytes)
	if err != nil {
		log.Fatal(nil, "Invalid X25519 private key", "err", err)
		return
	}

	// read encrypted files
	encKDK, err := os.ReadFile(encKDKFile)
	if err != nil {
		log.Fatal(nil, "Failed to read encrypted KDK", "err", err)
		return
	}
	encCKPayload, err := os.ReadFile(encCKFile)
	if err != nil {
		log.Fatal(nil, "Failed to read encrypted CK", "err", err)
		return
	}
	encContentPayload, err := os.ReadFile(encContentFile)
	if err != nil {
		log.Fatal(nil, "Failed to read encrypted content", "err", err)
		return
	}

	decryptor := nac.NewDecryptor(consumerKeyName, privKey)
	plaintext, err := decryptor.Decrypt(
		&nac.EncryptedContent{EncryptedPayload: encContentPayload},
		&nac.EncryptedCK{EncryptedPayload: encCKPayload},
		encKDK,
	)
	if err != nil {
		log.Fatal(nil, "Decryption failed", "err", err)
		return
	}

	os.Stdout.Write(plaintext)
	fmt.Fprintf(os.Stderr, "Decrypted %d bytes\n", len(plaintext))
}
