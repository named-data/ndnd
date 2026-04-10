package tools

import (
	"encoding/hex"
	"io"
	"os"
	"os/signal"
	"syscall"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/nac"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/spf13/cobra"
)

type PutChunks struct {
	expose  bool
	nacKek  string // hex KEK public key
	nacCred string // NAC credential prefix
}

// (AI GENERATED DESCRIPTION): Creates a Cobra command that publishes data chunks read from standard input under a specified name prefix, optionally registering the prefix with the client origin.
func CmdPutChunks() *cobra.Command {
	pc := PutChunks{}

	cmd := &cobra.Command{
		GroupID: "tools",
		Use:     "put PREFIX",
		Short:   "Publish data under a name prefix",
		Long: `Publish data under a name prefix.
This tool expects data from the standard input.`,
		Args:    cobra.ExactArgs(1),
		Example: `  ndnd put /my/example/data < data.bin`,
		Run:     pc.run,
	}

	cmd.Flags().BoolVar(&pc.expose, "expose", false, "Use client origin for prefix registration")
	cmd.Flags().StringVar(&pc.nacKek, "nac-kek", "", "NAC KEK public key (hex) for encryption")
	cmd.Flags().StringVar(&pc.nacCred, "nac-cred", "", "NAC credential prefix (required with --nac-kek)")
	return cmd
}

// (AI GENERATED DESCRIPTION): Returns the literal string `"put"` to identify the `PutChunks` operation (implementing the fmt.Stringer interface).
func (pc *PutChunks) String() string {
	return "put"
}

// (AI GENERATED DESCRIPTION): Ingests data from standard input, produces a named Data object in the NDN engine, announces its prefix, and blocks until a termination signal is received.
func (pc *PutChunks) run(_ *cobra.Command, args []string) {
	name, err := enc.NameFromStr(args[0])
	if err != nil {
		log.Fatal(pc, "Invalid object name", "name", args[0])
		return
	}

	// start face and engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		log.Fatal(pc, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// start object client
	cli := object.NewClient(app, storage.NewMemoryStore(), nil)
	err = cli.Start()
	if err != nil {
		log.Fatal(pc, "Unable to start object client", "err", err)
		return
	}
	defer cli.Stop()

	// read from stdin till eof
	var content enc.Wire
	for {
		buf := make([]byte, 8192)
		n, err := io.ReadFull(os.Stdin, buf)
		if n > 0 {
			content = append(content, buf[:n])
		}
		if err != nil {
			break
		}
	}

	// If NAC encryption is enabled, encrypt the content before publishing
	var encCKContent enc.Wire
	if pc.nacKek != "" {
		if pc.nacCred == "" {
			log.Fatal(pc, "--nac-cred is required when using --nac-kek")
			return
		}

		kekBytes, err := hex.DecodeString(pc.nacKek)
		if err != nil {
			log.Fatal(pc, "Invalid KEK hex", "err", err)
			return
		}
		pubKey, err := nac.DeserializePublicKey(kekBytes)
		if err != nil {
			log.Fatal(pc, "Invalid KEK public key", "err", err)
			return
		}

		kek := &nac.KeyEncryptionKey{PublicKey: pubKey, ID: make([]byte, 16)}
		copy(kek.ID, kekBytes[:16]) // use first 16 bytes of pubkey as ID for naming
		encryptor := nac.NewEncryptor(args[0], pc.nacCred, kek)

		encContent, encCK, err := encryptor.Encrypt(args[0]+"/data", content.Join())
		if err != nil {
			log.Fatal(pc, "NAC encryption failed", "err", err)
			return
		}

		content = enc.Wire{encContent.EncryptedPayload}
		encCKContent = enc.Wire{encCK.EncryptedPayload}
		log.Info(pc, "Content encrypted with NAC",
			"content_bytes", len(encContent.EncryptedPayload),
			"ck_bytes", len(encCK.EncryptedPayload))
	}

	// produce object
	vname, err := cli.Produce(ndn.ProduceArgs{
		Name:    name.WithVersion(enc.VersionUnixMicro),
		Content: content,
	})
	if err != nil {
		log.Fatal(pc, "Unable to produce object", "err", err)
		return
	}

	// If NAC, also publish the encrypted CK under <prefix>/CK
	if encCKContent != nil {
		ckName := name.Append(enc.NewGenericComponent("CK"))
		_, err := cli.Produce(ndn.ProduceArgs{
			Name:    ckName.WithVersion(enc.VersionUnixMicro),
			Content: encCKContent,
		})
		if err != nil {
			log.Fatal(pc, "Unable to produce encrypted CK", "err", err)
			return
		}
		log.Info(pc, "Encrypted CK published", "name", ckName)
	}

	content = nil // gc
	log.Info(pc, "Object produced", "name", vname)

	// announce the prefix
	cli.AnnouncePrefix(ndn.Announcement{
		Name:   name,
		Expose: pc.expose,
	})
	defer cli.WithdrawPrefix(name, nil)

	// wait forever
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigchan
	log.Info(nil, "Received signal - exiting", "signal", receivedSig)
}
