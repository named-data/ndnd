package tools

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/nac"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
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
	cmd.AddCommand(cmdNacEnroll())

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
	kekPubBytes, _ := nac.SerializePublicKey(kek.PublicKey)
	fmt.Printf("KEK ID: %s\n", hex.EncodeToString(kek.ID))
	fmt.Printf("KEK Public Key: %s\n", hex.EncodeToString(kekPubBytes))
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

func cmdNacEnroll() *cobra.Command {
	return &cobra.Command{
		Use:   "enroll NAC-PREFIX CERT-FILE KEY-FILE",
		Short: "Enroll for NAC access using NDNCERT-issued certificate",
		Long: `Enroll as an authorized NAC consumer using your NDNCERT-issued certificate.

This generates an X25519 encryption key pair, sends the public key along with
your certificate to the NAC server's ENROLL endpoint, and saves the private key.

The server verifies the certificate was signed by the CA, then authorizes your
identity for encrypted content access.`,
		Example: `  ndnd nac enroll /demo/nac client.cert client.key`,
		Args:    cobra.ExactArgs(3),
		Run:     runNacEnroll,
	}
}

func runNacEnroll(_ *cobra.Command, args []string) {
	nacPrefix := args[0]
	certFile := args[1]
	keyFile := args[2]

	// Load NDNCERT-issued certificate
	certFileBytes, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatal(nil, "Failed to read cert file", "err", err)
		return
	}
	_, certs, _ := sec.DecodeFile(certFileBytes)
	if len(certs) != 1 {
		log.Fatal(nil, "Cert file must contain exactly one certificate")
		return
	}

	// Load signing key (to prove ownership — though we send the cert itself for verification)
	keyFileBytes, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatal(nil, "Failed to read key file", "err", err)
		return
	}
	keys, _, _ := sec.DecodeFile(keyFileBytes)
	if len(keys) != 1 {
		log.Fatal(nil, "Key file must contain exactly one key")
		return
	}
	_ = keys[0] // signer available if needed in future

	// Generate X25519 key pair for NAC encryption
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(nil, "Failed to generate X25519 key", "err", err)
		return
	}
	x25519PubBytes := x25519Priv.PublicKey().Bytes()

	fmt.Fprintf(os.Stderr, "Generated X25519 key pair\n")
	fmt.Fprintf(os.Stderr, "  Public:  %s\n", hex.EncodeToString(x25519PubBytes))

	// Build enrollment payload: [32-byte X25519 pubkey][certificate wire]
	payload := make([]byte, 0, 32+len(certs[0]))
	payload = append(payload, x25519PubBytes...)
	payload = append(payload, certs[0]...)

	// Start engine
	eng := engine.NewBasicEngine(engine.NewDefaultFace())
	if err := eng.Start(); err != nil {
		log.Fatal(nil, "Engine start failed", "err", err)
		return
	}
	defer eng.Stop()

	// Send enrollment Interest to <nac-prefix>/ENROLL
	enrollName, err := enc.NameFromStr(nacPrefix + "/ENROLL")
	if err != nil {
		log.Fatal(nil, "Invalid NAC prefix", "err", err)
		return
	}

	fmt.Fprintf(os.Stderr, "Enrolling at %s...\n", enrollName)

	interest, err := eng.Spec().MakeInterest(enrollName, &ndn.InterestConfig{
		Lifetime: optional.Some(10 * time.Second),
		Nonce:    utils.ConvertNonce(eng.Timer().Nonce()),
	}, enc.Wire{payload}, nil)
	if err != nil {
		log.Fatal(nil, "Failed to make enrollment Interest", "err", err)
		return
	}

	ch := make(chan ndn.ExpressCallbackArgs, 1)
	eng.Express(interest, func(args ndn.ExpressCallbackArgs) { ch <- args })
	result := <-ch

	if result.Result != ndn.InterestResultData {
		log.Fatal(nil, "Enrollment failed", "result", result.Result)
		return
	}

	// Parse response
	response := result.Data.Content().Join()
	if len(response) < 3 || string(response[:3]) != "OK:" {
		fmt.Fprintf(os.Stderr, "Enrollment rejected: %s\n", string(response))
		os.Exit(1)
		return
	}

	// Response: "OK:" + KEK pub (32 bytes) + KEK ID (16 bytes)
	respBody := response[3:]
	if len(respBody) < 48 {
		log.Fatal(nil, "Invalid enrollment response (too short)")
		return
	}
	kekPubBytes := respBody[:32]
	kekID := respBody[32:48]

	fmt.Fprintf(os.Stderr, "\nEnrollment successful!\n")
	fmt.Fprintf(os.Stderr, "  KEK Public Key: %s\n", hex.EncodeToString(kekPubBytes))
	fmt.Fprintf(os.Stderr, "  KEK ID: %s\n", hex.EncodeToString(kekID))
	fmt.Fprintf(os.Stderr, "  NAC Private Key: %s\n", hex.EncodeToString(x25519Priv.Bytes()))
	fmt.Fprintf(os.Stderr, "\nSave your NAC private key — you'll need it to decrypt content.\n")

	// Print machine-readable output to stdout
	fmt.Printf("NAC_PRIVATE=%s\n", hex.EncodeToString(x25519Priv.Bytes()))
	fmt.Printf("NAC_PUBLIC=%s\n", hex.EncodeToString(x25519PubBytes))
	fmt.Printf("KEK_PUBLIC=%s\n", hex.EncodeToString(kekPubBytes))
	fmt.Printf("KEK_ID=%s\n", hex.EncodeToString(kekID))
}
