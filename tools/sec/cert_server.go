package sec

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
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/named-data/ndnd/std/security/ndncert/server"
	"github.com/spf13/cobra"
)

type CertServer struct {
	mockDNS bool
	dataDir string
}

func CmdCertServer() *cobra.Command {
	srv := CertServer{}

	cmd := &cobra.Command{
		Use:   "certca CA-CONFIG CA-CERT CA-KEY",
		Short: "NDNCERT Certificate Authority Server",
		Args:  cobra.ExactArgs(3),
		Run:   srv.run,
	}

	cmd.Flags().BoolVar(&srv.mockDNS, "mock-dns", false,
		"Mock DNS lookups (testing only)")
	cmd.Flags().StringVar(&srv.dataDir, "data-dir", "",
		"Persistent data directory (empty = in-memory only)")

	return cmd
}

func (c *CertServer) String() string { return "ndncert-ca" }

func (c *CertServer) run(_ *cobra.Command, args []string) {
	configFile, certFile, keyFile := args[0], args[1], args[2]

	config, err := server.LoadConfig(configFile)
	if err != nil {
		log.Fatal(c, "Bad config", "err", err)
		return
	}
	config.CaCertPath = certFile
	config.CaKeyPath = keyFile

	// load cert
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatal(c, "Can't read cert", "err", err)
		return
	}
	_, caCerts, _ := sec.DecodeFile(certBytes)
	if len(caCerts) != 1 {
		log.Fatal(c, "Need exactly one cert in file")
		return
	}

	// load key
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatal(c, "Can't read key", "err", err)
		return
	}
	keys, _, _ := sec.DecodeFile(keyBytes)
	if len(keys) != 1 {
		log.Fatal(c, "Need exactly one key in file")
		return
	}

	// engine
	ndnEngine := engine.NewBasicEngine(engine.NewDefaultFace())
	if err := ndnEngine.Start(); err != nil {
		log.Fatal(c, "Engine start failed", "err", err)
		return
	}
	defer ndnEngine.Stop()

	// ca server
	caServer, err := server.NewCaServer(ndnEngine, config, enc.Wire{caCerts[0]}, keys[0])
	if err != nil {
		log.Fatal(c, "Failed to create CA", "err", err)
		return
	}
	if config.SupportsChallenge(ndncert.KwEmail) {
		password := ""
		if config.Email.SMTPPasswordEnv != "" {
			password = os.Getenv(config.Email.SMTPPasswordEnv)
		}
		sender, err := server.NewSMTPEmailSender(config.Email, password)
		if err != nil {
			log.Fatal(c, "Invalid email challenge configuration", "err", err)
			return
		}
		caServer.SetEmailSender(sender)
	}

	if c.dataDir != "" {
		if err := os.MkdirAll(c.dataDir, 0700); err != nil {
			log.Fatal(c, "Failed to create data dir", "err", err)
			return
		}
		caObjStore, err := storage.NewBadgerStore(c.dataDir + "/ca-objects")
		if err != nil {
			log.Fatal(c, "Failed to open CA object store", "err", err)
			return
		}
		defer caObjStore.Close()
		caServer.SetObjectStore(caObjStore)
		log.Info(c, "CA using persistent storage", "dir", c.dataDir)
	}

	if c.mockDNS {
		log.Warn(c, "Mock DNS enabled -- do not use in production")
		caServer.MockDNS = true
	}

	if err := caServer.Start(); err != nil {
		log.Fatal(c, "CA start failed", "err", err)
		return
	}
	defer caServer.Stop()

	fmt.Fprintf(os.Stderr, "\nNDNCERT CA running: %s\n", config.CaPrefix)
	for _, ch := range config.SupportedChallenges {
		fmt.Fprintf(os.Stderr, "  challenge: %s\n", ch.Name)
	}
	if c.mockDNS {
		fmt.Fprintf(os.Stderr, "  *** mock DNS enabled ***\n")
	}

	// Expose prefixes to the network via PET prefix insertion
	store := storage.NewMemoryStore()
	cli := object.NewClient(ndnEngine, store, nil)
	if err := cli.Start(); err != nil {
		log.Fatal(c, "Object client start failed", "err", err)
		return
	}
	defer cli.Stop()

	caName, _ := enc.NameFromStr(config.CaPrefix)
	cli.AnnouncePrefix(ndn.Announcement{Name: caName, Expose: true})
	defer cli.WithdrawPrefix(caName, nil)
	log.Info(c, "Exposed CA prefix", "prefix", config.CaPrefix)

	fmt.Fprintf(os.Stderr, "\nCtrl+C to stop\n\n")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info(c, "Shutting down")
}
