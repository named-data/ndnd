package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	sec_pib "github.com/named-data/ndnd/std/security/pib"
	"github.com/named-data/ndnd/std/utils"
)

var app ndn.Engine
var pib *sec_pib.SqlitePib

func onInterest(args ndn.InterestHandlerArgs) {
	interest := args.Interest

	fmt.Printf(">> I: %s\n", interest.Name().String())
	content := []byte("Hello, world!")

	idName, _ := enc.NameFromStr("/test")
	identity := pib.GetIdentity(idName)
	cert := identity.FindCert(func(_ sec_pib.Cert) bool { return true })
	signer := cert.AsSigner()

	data, err := app.Spec().MakeData(
		interest.Name(),
		&ndn.DataConfig{
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
			Freshness:   utils.IdPtr(10 * time.Second),
		},
		enc.Wire{content},
		signer)
	if err != nil {
		log.WithField("module", "main").Errorf("unable to encode data: %+v", err)
		return
	}
	err = args.Reply(data.Wire)
	if err != nil {
		log.WithField("module", "main").Errorf("unable to reply with data: %+v", err)
		return
	}
	fmt.Printf("<< D: %s\n", interest.Name().String())
	fmt.Printf("Content: (size: %d)\n", len(content))
	fmt.Printf("\n")
}

func main() {
	log.SetLevel(log.InfoLevel)
	logger := log.WithField("module", "main")

	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err := app.Start()
	if err != nil {
		logger.Fatalf("Unable to start engine: %+v", err)
		return
	}
	defer app.Stop()

	homedir, _ := os.UserHomeDir()
	tpm := sec_pib.NewFileTpm(filepath.Join(homedir, ".ndn/ndnsec-key-file"))
	pib = sec_pib.NewSqlitePib(filepath.Join(homedir, ".ndn/pib.db"), tpm)

	prefix, _ := enc.NameFromStr("/example/testApp")
	err = app.AttachHandler(prefix, onInterest)
	if err != nil {
		logger.Errorf("Unable to register handler: %+v", err)
		return
	}
	err = app.RegisterRoute(prefix)
	if err != nil {
		logger.Errorf("Unable to register route: %+v", err)
		return
	}

	fmt.Print("Start serving ...")
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	logger.Infof("Received signal %+v - exiting", receivedSig)
}
