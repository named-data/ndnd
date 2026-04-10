package tools

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/nac"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
	"github.com/spf13/cobra"
)

type CatChunks struct {
	nacKey     string // hex X25519 private key for NAC decryption
	nacAccess  string // NAC access prefix (for KDK fetch)
	nacDataset string // NAC dataset name
	nacKeyID   string // hex KEK ID (for constructing KDK name)
	nacIdent   string // consumer key name (NDNCERT identity)
}

// (AI GENERATED DESCRIPTION): Creates a Cobra command that retrieves the data object for a given name prefix and writes its content to standard output.
func CmdCatChunks() *cobra.Command {
	cc := CatChunks{}

	cmd := &cobra.Command{
		GroupID: "tools",
		Use:     "cat PREFIX",
		Short:   "Retrieve object under a name prefix",
		Long: `Retrieve an object with the specified name.
The object contents are written to stdout on success.

With NAC flags, also fetches the encrypted content key and KDK,
then decrypts the content before writing to stdout.`,
		Args:    cobra.ExactArgs(1),
		Example: `  ndnd cat /my/example/data > data.bin`,
		Run:     cc.run,
	}

	cmd.Flags().StringVar(&cc.nacKey, "nac-key", "", "NAC X25519 private key (hex) for decryption")
	cmd.Flags().StringVar(&cc.nacAccess, "nac-access", "", "NAC access prefix (for KDK fetch)")
	cmd.Flags().StringVar(&cc.nacDataset, "nac-dataset", "default", "NAC dataset name")
	cmd.Flags().StringVar(&cc.nacKeyID, "nac-kek-id", "", "NAC KEK ID (hex, for constructing KDK name)")
	cmd.Flags().StringVar(&cc.nacIdent, "nac-ident", "", "Consumer key name (NDNCERT identity)")

	return cmd
}

// (AI GENERATED DESCRIPTION): Returns the literal string `"cat"` as the textual representation of a `CatChunks` instance.
func (cc *CatChunks) String() string {
	return "cat"
}

// (AI GENERATED DESCRIPTION): Fetches an NDN object by name, streams its payload to standard output, and prints fetch statistics and progress to standard error.
func (cc *CatChunks) run(_ *cobra.Command, args []string) {
	name, err := enc.NameFromStr(args[0])
	if err != nil {
		log.Fatal(cc, "Invalid name", "name", args[0])
		return
	}

	// start face and engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		log.Fatal(cc, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// start object client
	cli := object.NewClient(app, storage.NewMemoryStore(), nil)
	err = cli.Start()
	if err != nil {
		log.Fatal(cc, "Unable to start object client", "err", err)
		return
	}
	defer cli.Stop()

	done := make(chan ndn.ConsumeState)
	t1, t2 := time.Now(), time.Now()

	// fetch object
	progress := 0
	cli.ConsumeExt(ndn.ConsumeExtArgs{
		Name: name,
		Callback: func(state ndn.ConsumeState) {
			t2 = time.Now()
			done <- state
		},
		OnProgress: func(state ndn.ConsumeState) {
			if state.Progress()-progress >= 1000 {
				progress = state.Progress()
				log.Debug(cc, "Consume progress", "progress", float64(state.Progress())/float64(state.ProgressMax())*100)
			}
		},
	})
	state := <-done

	if state.Error() != nil {
		log.Fatal(cc, "Error fetching object", "err", state.Error())
		return
	}

	// Collect content bytes
	var contentBytes []byte
	for _, chunk := range state.Content() {
		contentBytes = append(contentBytes, chunk...)
	}

	// If NAC decryption is enabled
	if cc.nacKey != "" {
		if cc.nacAccess == "" || cc.nacKeyID == "" || cc.nacIdent == "" {
			log.Fatal(cc, "--nac-access, --nac-kek-id, and --nac-ident are required with --nac-key")
			return
		}

		privKeyBytes, err := hex.DecodeString(cc.nacKey)
		if err != nil {
			log.Fatal(cc, "Invalid NAC private key hex", "err", err)
			return
		}
		privKey, err := nac.DeserializePrivateKey(privKeyBytes)
		if err != nil {
			log.Fatal(cc, "Invalid NAC X25519 private key", "err", err)
			return
		}
		kekID, err := hex.DecodeString(cc.nacKeyID)
		if err != nil {
			log.Fatal(cc, "Invalid KEK ID hex", "err", err)
			return
		}

		// Fetch the encrypted CK from <prefix>/CK
		ckName := name.Append(enc.NewGenericComponent("CK"))
		fmt.Fprintf(os.Stderr, "Fetching encrypted CK from %s...\n", ckName)
		ckDone := make(chan ndn.ConsumeState)
		cli.ConsumeExt(ndn.ConsumeExtArgs{
			Name:     ckName,
			Callback: func(s ndn.ConsumeState) { ckDone <- s },
		})
		ckState := <-ckDone
		if ckState.Error() != nil {
			log.Fatal(cc, "Failed to fetch encrypted CK", "err", ckState.Error())
			return
		}
		var encCKBytes []byte
		for _, chunk := range ckState.Content() {
			encCKBytes = append(encCKBytes, chunk...)
		}
		fmt.Fprintf(os.Stderr, "Encrypted CK: %d bytes\n", len(encCKBytes))

		// Fetch the encrypted KDK from the NAC server
		kdkForName := nac.EncryptedKDKName(cc.nacAccess, cc.nacDataset, kekID, cc.nacIdent)
		fmt.Fprintf(os.Stderr, "Fetching KDK from %s...\n", kdkForName)

		kdkNdnName, _ := enc.NameFromStr(kdkForName)
		kdkCh := make(chan ndn.ExpressCallbackArgs, 1)
		kdkInterest, _ := app.Spec().MakeInterest(kdkNdnName, &ndn.InterestConfig{
			Lifetime: optional.Some(10 * time.Second),
			Nonce:    utils.ConvertNonce(app.Timer().Nonce()),
		}, nil, nil)
		app.Express(kdkInterest, func(args ndn.ExpressCallbackArgs) { kdkCh <- args })
		kdkResult := <-kdkCh
		if kdkResult.Result != ndn.InterestResultData {
			log.Fatal(cc, "Failed to fetch KDK", "result", kdkResult.Result)
			return
		}
		encKDKBytes := kdkResult.Data.Content().Join()
		fmt.Fprintf(os.Stderr, "Encrypted KDK: %d bytes\n", len(encKDKBytes))

		// Decrypt the chain: KDK -> CK -> content
		decryptor := nac.NewDecryptor(cc.nacIdent, privKey)
		plaintext, err := decryptor.Decrypt(
			&nac.EncryptedContent{EncryptedPayload: contentBytes},
			&nac.EncryptedCK{EncryptedPayload: encCKBytes},
			encKDKBytes,
		)
		if err != nil {
			log.Fatal(cc, "NAC decryption failed", "err", err)
			return
		}
		contentBytes = plaintext
		fmt.Fprintf(os.Stderr, "Decrypted: %d bytes\n", len(plaintext))
	}

	// write to stdout
	os.Stdout.Write(contentBytes)

	// statistics
	fmt.Fprintf(os.Stderr, "Object fetched %s\n", state.Name())
	fmt.Fprintf(os.Stderr, "Content: %d bytes\n", len(contentBytes))
	fmt.Fprintf(os.Stderr, "Time taken: %s\n", t2.Sub(t1))
	fmt.Fprintf(os.Stderr, "Throughput: %f Mbit/s\n", float64(len(contentBytes)*8)/t2.Sub(t1).Seconds()/1e6)
}
