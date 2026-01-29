package tools

import (
	"io"
	"os"
	"os/signal"
	"syscall"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/spf13/cobra"
)

type PutChunks struct {
	expose bool
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

	// produce object
	vname, err := cli.Produce(ndn.ProduceArgs{
		Name:    name.WithVersion(enc.VersionUnixMicro),
		Content: content,
	})
	if err != nil {
		log.Fatal(pc, "Unable to produce object", "err", err)
		return
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
