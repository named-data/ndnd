package tools

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/spf13/cobra"
)

type PingServer struct {
	app    ndn.Engine
	signer ndn.Signer
	name   enc.Name
	nRecv  int
	expose bool
}

func CmdPingServer() *cobra.Command {
	ps := PingServer{}

	cmd := &cobra.Command{
		GroupID: "tools",
		Use:     "pingserver PREFIX",
		Short:   "Start a ping server under a name prefix",
		Args:    cobra.ExactArgs(1),
		Example: `  ndnd pingserver /my/prefix`,
		Run:     ps.run,
	}

	cmd.Flags().BoolVar(&ps.expose, "expose", false, "Use client origin for prefix registration")
	return cmd
}

func (ps *PingServer) String() string {
	return "ping-server"
}

func (ps *PingServer) run(_ *cobra.Command, args []string) {
	name, err := enc.NameFromStr(args[0])
	if err != nil {
		log.Fatal(ps, "Invalid prefix", "name", args[0])
		return
	}
	ps.name = name.Append(enc.NewGenericComponent("ping"))

	ps.signer = signer.NewSha256Signer()
	ps.app = engine.NewBasicEngine(engine.NewDefaultFace())
	err = ps.app.Start()
	if err != nil {
		log.Fatal(ps, "Unable to start engine", "err", err)
		return
	}
	defer ps.app.Stop()

	err = ps.app.AttachHandler(ps.name, ps.onInterest)
	if err != nil {
		log.Fatal(ps, "Unable to register handler", "err", err)
		return
	}

	cli := object.NewClient(ps.app, storage.NewMemoryStore(), nil)
	if err = cli.Start(); err != nil {
		log.Fatal(ps, "Unable to start object client", "err", err)
		return
	}
	defer cli.Stop()

	cli.AnnouncePrefix(ndn.Announcement{
		Name:   name,
		Expose: ps.expose,
	})
	defer cli.WithdrawPrefix(name, nil)

	fmt.Printf("PING SERVER %s\n", ps.name)
	defer ps.stats()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	<-sigchan
}

func (ps *PingServer) stats() {
	fmt.Printf("\n--- %s ping server statistics ---\n", ps.name)
	fmt.Printf("%d Interests processed\n", ps.nRecv)
}

func (ps *PingServer) onInterest(args ndn.InterestHandlerArgs) {
	fmt.Printf("interest received: %s\n", args.Interest.Name())
	ps.nRecv++

	data, err := ps.app.Spec().MakeData(
		args.Interest.Name(),
		&ndn.DataConfig{
			ContentType: optional.Some(ndn.ContentTypeBlob),
		},
		args.Interest.AppParam(),
		ps.signer)
	if err != nil {
		log.Fatal(ps, "Unable to encode data", "err", err)
		return
	}
	err = args.Reply(data.Wire)
	if err != nil {
		log.Fatal(ps, "Unable to reply with data", "err", err)
		return
	}
}
