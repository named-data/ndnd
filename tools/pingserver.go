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
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
)

type PingServer struct {
	args   []string
	app    ndn.Engine
	signer ndn.Signer

	name  enc.Name
	nRecv int
}

func RunPingServer(args []string) {
	(&PingServer{
		args:   args,
		signer: sec.NewSha256Signer(),
	}).run()
}

func (ps *PingServer) String() string {
	return "ping-server"
}

func (ps *PingServer) usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <prefix>\n", ps.args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Starts a NDN ping server that responds to Interests under a prefix.\n")
}

func (ps *PingServer) run() {
	if len(ps.args) < 2 {
		ps.usage()
		os.Exit(3)
	}

	prefix, err := enc.NameFromStr(ps.args[1])
	if err != nil {
		log.Fatal(ps, "Invalid prefix", "name", ps.args[1])
		return
	}
	ps.name = prefix.Append(enc.NewStringComponent(enc.TypeGenericNameComponent, "ping"))

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

	err = ps.app.RegisterRoute(ps.name)
	if err != nil {
		log.Fatal(ps, "Unable to register route", "err", err)
		return
	}

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
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
		},
		args.Interest.AppParam(),
		ps.signer)
	if err != nil {
		log.Error(ps, "Unable to encode data", "err", err)
		return
	}
	err = args.Reply(data.Wire)
	if err != nil {
		log.Error(ps, "Unable to reply with data", "err", err)
		return
	}
}
