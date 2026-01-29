package sec

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert"
	spec_ndncert "github.com/named-data/ndnd/std/security/ndncert/tlv"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/spf13/cobra"
)

type CertClient struct {
	flags struct {
		keyFile   string
		outFile   string
		challenge string
		email     string
		domain    string
		noprobe   bool
	}

	caCert    []byte
	caPrefix  enc.Name
	signer    ndn.Signer
	challenge ndncert.Challenge
}

// (AI GENERATED DESCRIPTION): Creates a Cobra command for the NDNCERT certificate client, setting its usage, flags, and run logic.
func CmdCertCli() *cobra.Command {
	client := CertClient{}

	cmd := &cobra.Command{
		GroupID: "sec",
		Use:     "certcli CA-CERT-FILE",
		Short:   "NDNCERT Certificate Client",
		Long: `Interactive client for the NDNCERT CA.

This client can be used to request a new certificate from the NDNCERT CA.
It reads the CA root certificate from the specified file and interacts with
the CA to obtain a new certificate.`,
		Example: `  https://github.com/named-data/ndnd/blob/main/docs/certcli.md`,
		Args:    cobra.ExactArgs(1),
		Run:     client.run,
	}

	cmd.Flags().StringVarP(&client.flags.outFile, "output", "o", "", `Output filename without extension (default "stdout")`)
	cmd.Flags().StringVarP(&client.flags.keyFile, "key", "k", "", `File with NDN key to certify (default "keygen")`)
	cmd.Flags().StringVarP(&client.flags.challenge, "challenge", "c", "", `Challenge type: email, pin, dns (default "ask")`)
	cmd.Flags().StringVar(&client.flags.email, "email", "", `Email address for probe and email challenge`)
	cmd.Flags().StringVar(&client.flags.domain, "domain", "", `Domain name for DNS challenge`)
	cmd.Flags().BoolVar(&client.flags.noprobe, "no-probe", false, `Skip probe and use the provided key directly`)

	return cmd
}

// (AI GENERATED DESCRIPTION): Returns the string representation of the CertClient, which is the constant "ndncert-cli".
func (c *CertClient) String() string {
	return "ndncert-cli"
}

// (AI GENERATED DESCRIPTION): Loads the CA certificate and optional private key, selects a challenge, and initiates the certificate client.
func (c *CertClient) run(_ *cobra.Command, args []string) {
	// Read CA certificate
	caCertFile, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatal(c, "Unable to read CA certificate file", "file", args[0])
		return
	}
	_, caCerts, _ := sec.DecodeFile(caCertFile)
	if len(caCerts) != 1 {
		log.Fatal(c, "CA certificate file must contain exactly one certificate", "file", args[0])
		return
	}
	c.caCert = caCerts[0]

	// Read private key if specified
	if keyFile := c.flags.keyFile; keyFile != "" {
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatal(c, "Unable to read private key file", "file", keyFile)
			return
		}
		keys, _, _ := sec.DecodeFile(keyBytes)
		if len(keys) != 1 {
			log.Fatal(c, "Private key file must contain exactly one key", "file", keyFile)
			return
		}
		c.signer = keys[0]
	}

	// Choose challenge type
	c.challenge = c.chooseChallenge()

	// Run the client
	c.client()
}

// chooseChallenge asks the user to choose a challenge type.
// It then prompts the user for the necessary information and returns the challenge.
func (c *CertClient) chooseChallenge() ndncert.Challenge {
	defer fmt.Fprintln(os.Stderr)

	challenges := []string{ndncert.KwEmail, ndncert.KwPin, ndncert.KwDns}

	if c.flags.challenge == "" {
		i := c.chooseOpts("Please choose a challenge type:", challenges)
		c.flags.challenge = challenges[i]
	}

	switch c.flags.challenge {
	case ndncert.KwEmail:
		if c.flags.email == "" {
			c.scanln("Enter your email address", &c.flags.email)
		}
		return &ndncert.ChallengeEmail{
			Email: c.flags.email,
			CodeCallback: func(status string) (code string) {
				fmt.Fprintf(os.Stderr, "\n")
				fmt.Fprintf(os.Stderr, "Challenge Status: %s\n", status)
				fmt.Fprintf(os.Stderr, "Enter the code sent to your email address: ")
				fmt.Scanln(&code)
				return code
			},
		}

	case ndncert.KwPin:
		return &ndncert.ChallengePin{
			CodeCallback: func(status string) (code string) {
				fmt.Fprintf(os.Stderr, "\n")
				fmt.Fprintf(os.Stderr, "Challenge Status: %s\n", status)
				fmt.Fprintf(os.Stderr, "Enter the secret PIN: ")
				fmt.Scanln(&code)
				return code
			},
		}

	case ndncert.KwDns:
		return &ndncert.ChallengeDns{
			DomainCallback: func(status string) string {
				if c.flags.domain == "" {
					c.scanln("Enter the domain name you want to validate", &c.flags.domain)
				}
				return c.flags.domain
			},
			ConfirmationCallback: func(recordName, expectedValue, status string) string {
				fmt.Fprintf(os.Stderr, "\n")
				switch status {
				case "need-record":
					fmt.Fprintf(os.Stderr, "=== DNS CHALLENGE SETUP ===\n")
					fmt.Fprintf(os.Stderr, "Please create the following DNS TXT record:\n\n")
					fmt.Fprintf(os.Stderr, "Record Name: %s\n", recordName)
					fmt.Fprintf(os.Stderr, "Record Type: TXT\n")
					fmt.Fprintf(os.Stderr, "Record Value: %s\n\n", expectedValue)
					fmt.Fprintf(os.Stderr, "Example DNS configuration:\n")
					fmt.Fprintf(os.Stderr, "%s IN TXT \"%s\"\n\n", recordName, expectedValue)
					fmt.Fprintf(os.Stderr, "After creating the DNS TXT record, press ENTER to continue verification...")

				case "wrong-record":
					fmt.Fprintf(os.Stderr, "DNS verification failed. Please check that:\n")
					fmt.Fprintf(os.Stderr, "1. The TXT record exists and has the correct value: %s\n", expectedValue)
					fmt.Fprintf(os.Stderr, "2. DNS propagation has completed (may take a few minutes)\n")
					fmt.Fprintf(os.Stderr, "3. The record name is correct: %s\n", recordName)
					fmt.Fprintf(os.Stderr, "Press ENTER to retry verification...")

				case "ready-for-validation":
					fmt.Fprintf(os.Stderr, "Performing DNS verification...\n")

				default:
					fmt.Fprintf(os.Stderr, "DNS Challenge Status: %s\n", status)
					if status != "ready-for-validation" {
						fmt.Fprintf(os.Stderr, "Press ENTER to continue...")
					}
				}

				if status != "ready-for-validation" {
					var input string
					fmt.Scanln(&input)
				}
				return "ready"
			},
		}

	default:
		fmt.Fprintf(os.Stderr, "Invalid challenge selected: %s\n", c.flags.challenge)
		os.Exit(3)
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Obtains an NDN certificate from a CA by starting an NDN engine, configuring a signer (generating one if necessary), performing a DNS challenge when required, requesting the certificate, and writing the resulting PEM‑encoded certificate and optional key to stdout or to specified files.
func (c *CertClient) client() {
	// Start the engine
	engine := engine.NewBasicEngine(engine.NewDefaultFace())
	err := engine.Start()
	if err != nil {
		log.Fatal(c, "Unable to start engine", "err", err)
		return
	}
	defer engine.Stop()

	// Create ndncert client
	certClient, err := ndncert.NewClient(engine, c.caCert)
	if err != nil {
		log.Fatal(c, "Unable to create ndncert client", "err", err)
		return
	}
	c.caPrefix = certClient.CaPrefix()
	_, isDns := c.challenge.(*ndncert.ChallengeDns)

	// Set signer if provided
	if c.signer != nil {
		certClient.SetSigner(c.signer)
	}

	if isDns {
		if c.flags.domain == "" {
			c.scanln("Enter your domain name", &c.flags.domain)
		}
		if c.signer == nil {
			if len(c.caPrefix) == 0 {
				log.Fatal(c, "CA prefix unavailable for DNS challenge")
				return
			}

			identity := c.caPrefix.Append(enc.NewGenericComponent(c.flags.domain))
			keyName := sec.MakeKeyName(identity)
			signer, err := sig.KeygenEcc(keyName, elliptic.P256())
			if err != nil {
				log.Fatal(c, "Unable to generate key for DNS identity", "err", err)
				return
			}
			c.signer = signer
			certClient.SetSigner(signer)
		}
	}

	disableProbe := c.flags.noprobe
	if isDns && !disableProbe {
		disableProbe = true
	}

	// Start the certificate request
	certRes, err := certClient.RequestCert(ndncert.RequestCertArgs{
		Challenge: c.challenge,
		OnProfile: func(profile *spec_ndncert.CaProfile) error {
			c.printCaProfile(profile)
			return nil
		},
		DisableProbe: disableProbe,
		OnProbeParam: func(key string) ([]byte, error) {
			switch key {
			case ndncert.KwEmail:
				if isDns {
					if c.flags.email == "" {
						return nil, nil
					}
					return []byte(c.flags.email), nil
				}
				if c.flags.email == "" {
					c.scanln("Enter your email address", &c.flags.email)
				}
				return []byte(c.flags.email), nil

			case ndncert.KwDomain:
				if c.flags.domain == "" {
					c.scanln("Enter your domain name", &c.flags.domain)
				}

				return []byte(c.flags.domain), nil

			default:
				var val string
				c.scanln(fmt.Sprintf("Enter probing parameter '%s'", key), &val)
				return []byte(val), nil
			}
		},
		OnChooseKey: func(suggestions []enc.Name) int {
			suggestionsStr := make([]string, 0, len(suggestions))
			for _, sgst := range suggestions {
				suggestionsStr = append(suggestionsStr, sgst.String())
			}
			return c.chooseOpts("Please choose a key name:", suggestionsStr)
		},
		OnKeyChosen: func(keyName enc.Name) error {
			fmt.Fprintf(os.Stderr, "Certifying key: %s\n", keyName)
			return nil
		},
	})
	if err != nil {
		// Handle mismatched key name
		var pmErr ndncert.ErrSignerProbeMismatch
		if errors.As(err, &pmErr) {
			fmt.Fprintf(os.Stderr, "Key name does not match CA probe response:\n")
			fmt.Fprintf(os.Stderr, "  %s\n", pmErr.KeyName)
			fmt.Fprintf(os.Stderr, "CA suggestions:\n")
			for _, sgst := range pmErr.Suggested {
				fmt.Fprintf(os.Stderr, "  %s\n", sgst)
			}
			os.Exit(1)
			return
		}

		// Handle no key suggestions from PROBE step
		if errors.Is(err, ndncert.ErrNoKeySuggestions) {
			fmt.Fprintf(os.Stderr, "No key suggestions from the CA\n")
			fmt.Fprintf(os.Stderr, "Please provide a key file with -k\n")
			os.Exit(1)
			return
		}

		// Handle other errors
		log.Fatal(c, err.Error())
		return
	}

	// PEM encode the certificate
	certBytes, err := sec.PemEncode(certRes.CertWire.Join())
	if err != nil {
		log.Fatal(c, "Unable to PEM encode certificate", "err", err)
		return
	}

	// Marshal the key if not specified as file
	var keyBytes []byte = nil
	if c.flags.keyFile == "" {
		keyWire, err := sig.MarshalSecret(certRes.Signer)
		if err != nil {
			log.Fatal(c, "Unable to marshal key", "err", err)
			return
		}

		keyBytes, err = sec.PemEncode(keyWire.Join())
		if err != nil {
			log.Error(c, "Unable to PEM encode key", "err", err)
		}
	}

	if c.flags.outFile == "" {
		// Write the key and certificate to stdout
		if len(keyBytes) > 0 {
			os.Stdout.Write(keyBytes)
			os.Stdout.Write([]byte("\n"))
		}
		os.Stdout.Write(certBytes)
	} else {
		// Write the key to a file
		if len(keyBytes) > 0 {
			err := os.WriteFile(c.flags.outFile+".key", keyBytes, 0600)
			if err != nil {
				log.Fatal(c, "Unable to write key file", "err", err)
				return
			}
		}

		// Write the certificate to a file
		err := os.WriteFile(c.flags.outFile+".cert", certBytes, 0644)
		if err != nil {
			log.Fatal(c, "Unable to write certificate file", "err", err)
			return
		}
	}
}

// (AI GENERATED DESCRIPTION): Presents a numbered list of options to the user, reads either the option string or its numeric index, and returns the selected option’s zero‑based index, retrying until a valid choice is made.
func (c *CertClient) chooseOpts(msg string, opts []string) int {
	fmt.Fprintf(os.Stderr, "%s\n", msg)
	for i, opt := range opts {
		fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, opt)
	}
	fmt.Fprintf(os.Stderr, "Choice: ")

	var choice string
	fmt.Scanln(&choice)

	// search by name
	for i, opt := range opts {
		if choice == opt {
			return i
		}
	}

	// search by index
	index, err := strconv.Atoi(choice)
	if err == nil {
		if index >= 1 && index <= len(opts) {
			return index - 1
		}
	}

	fmt.Fprintf(os.Stderr, "Invalid choice: %s\n\n", choice)

	return c.chooseOpts(msg, opts)
}

// (AI GENERATED DESCRIPTION): Prints the details of a CA profile (info, name, maximum validity period, and probe keys) to standard error.
func (c *CertClient) printCaProfile(profile *spec_ndncert.CaProfile) {
	fmt.Fprintln(os.Stderr, "=============== CA Profile ================")
	fmt.Fprintln(os.Stderr, profile.CaInfo)
	fmt.Fprintln(os.Stderr, "Name:", profile.CaPrefix.Name)
	fmt.Fprintln(os.Stderr, "Max Validity:", time.Duration(profile.MaxValidPeriod)*time.Second)
	fmt.Fprintln(os.Stderr, "Probe Keys:", profile.ParamKey)
	fmt.Fprintln(os.Stderr, "===========================================")
	fmt.Fprintln(os.Stderr)
}

// (AI GENERATED DESCRIPTION): Prompts the user with the given message, reads a line of input into the supplied string pointer, and exits with an error if the entered value is empty.
func (c *CertClient) scanln(msg string, val *string) {
	fmt.Fprintf(os.Stderr, "%s: ", msg)
	fmt.Scanln(val)
	if *val == "" {
		fmt.Fprintf(os.Stderr, "Invalid value entered\n")
		os.Exit(3)
	}
}
