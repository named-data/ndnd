package sec

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/nac"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert/server"
	sig "github.com/named-data/ndnd/std/security/signer"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/spf13/cobra"
)

type CertServer struct {
	mockDNS    bool
	nacPrefix  string
	nacDataset string
}

func CmdCertServer() *cobra.Command {
	srv := CertServer{}

	cmd := &cobra.Command{
		GroupID: "sec",
		Use:     "certca CA-CONFIG CA-CERT CA-KEY",
		Short:   "NDNCERT Certificate Authority Server",
		Args:    cobra.ExactArgs(3),
		Run:     srv.run,
	}

	cmd.Flags().BoolVar(&srv.mockDNS, "mock-dns", false,
		"Mock DNS lookups (testing only)")
	cmd.Flags().StringVar(&srv.nacPrefix, "nac", "",
		"Enable NAC key server at this access prefix (e.g., /demo)")
	cmd.Flags().StringVar(&srv.nacDataset, "nac-dataset", "default",
		"NAC dataset name for namespace scoping")

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

	// Start NAC key server if --nac is set
	if c.nacPrefix != "" {
		nacKeyName, _ := enc.NameFromStr(c.nacPrefix + "/KEY/nac-server")
		nacSigner, err := sig.KeygenEd25519(nacKeyName)
		if err != nil {
			log.Fatal(c, "Failed to generate NAC signer", "err", err)
			return
		}

		nacServer, err := nac.NewKeyServer(ndnEngine, nacSigner, c.nacPrefix, c.nacDataset)
		if err != nil {
			log.Fatal(c, "Failed to create NAC server", "err", err)
			return
		}

		caCertData, _, err := spec.Spec{}.ReadData(enc.NewBufferView(caCerts[0]))
		if err != nil {
			log.Fatal(c, "Failed to parse CA cert for NAC", "err", err)
			return
		}
		nacServer.RegisterCACert(caCertData)

		if err := nacServer.Start(); err != nil {
			log.Fatal(c, "NAC server start failed", "err", err)
			return
		}
		defer nacServer.Stop()

		kek := nacServer.AccessManager().KEK()
		kekPubBytes, _ := nac.SerializePublicKey(kek.PublicKey)
		nacNs := c.nacPrefix + "/NAC/" + c.nacDataset
		fmt.Fprintf(os.Stderr, "\nNAC key server running: %s\n", nacNs)
		fmt.Fprintf(os.Stderr, "  KEK ID: %x\n", kek.ID)
		fmt.Fprintf(os.Stderr, "  KEK Public Key: %x\n", kekPubBytes)
		fmt.Fprintf(os.Stderr, "  Enrollment: %s/ENROLL\n", nacNs)
	}

	fmt.Fprintf(os.Stderr, "\nCtrl+C to stop\n\n")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info(c, "Shutting down")
}
