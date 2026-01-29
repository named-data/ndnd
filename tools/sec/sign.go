package sec

import (
	"fmt"
	"io"
	"os"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security"
	"github.com/spf13/cobra"
)

// YYYYMMDDhhmmss
const TIME_LAYOUT = "20060102150405"

type ToolSignCert struct {
	Start  string
	End    string
	Info   string
	Issuer string
}

// (AI GENERATED DESCRIPTION): Sets up the `sign-cert` CLI subcommand, adding flags for validity period, additional info, and issuer, and binds it to execute the `signCert` handler.
func (t *ToolSignCert) configure(root *cobra.Command) {
	cmd := &cobra.Command{
		GroupID: "key",
		Use:     "sign-cert KEY-FILE",
		Short:   "Sign a new NDN certificate",
		Long: `Sign a new NDN certificate

Expects CSR input on stdin.
Signer key and CSR can be TLV or PEM encoded.

CSR can be either a self-signed certificate or a secret key.
To generate a self-signed certificate, provide the same key
file as both the signer key and the CSR.`,
		Args: cobra.ExactArgs(1),
		Example: `  ndnd sec sign-cert alice.key < alice.key > alice.cert
  ndnd sec sign-cert alice.key --issuer ALICE < bob.csr > bob.cert`,
		Run: t.signCert,
	}
	cmd.Flags().StringVar(&t.Start, "start", "now", "Validity start time in YYYYMMDDhhmmss format")
	cmd.Flags().StringVar(&t.End, "end", "now + 1 year", "Validity end time in YYYYMMDDhhmmss format")
	cmd.Flags().StringVar(&t.Info, "info", "", "Additional info to be included in the certificate")
	cmd.Flags().StringVar(&t.Issuer, "issuer", "NA", "Issuer ID to be included in the certificate name")
	root.AddCommand(cmd)
}

// (AI GENERATED DESCRIPTION): Signs a CSR read from standard input with a single key file and outputs the resulting PEM‑encoded certificate.
func (t *ToolSignCert) signCert(_ *cobra.Command, args []string) {
	keysFile, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open key file: %s\n", err)
		os.Exit(1)
	}
	defer keysFile.Close()

	keysBytes, err := io.ReadAll(keysFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read key file: %s\n", err)
		os.Exit(1)
	}

	csrsBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read CSR: %s\n", err)
		os.Exit(1)
	}

	signers, _, _ := security.DecodeFile(keysBytes)
	if len(signers) != 1 {
		fmt.Fprintf(os.Stderr, "Expected exactly one key, got %d\n", len(signers))
		os.Exit(1)
	}
	signer := signers[0]

	csrDatasBytes := security.PemDecode(csrsBytes)
	if len(csrDatasBytes) != 1 {
		fmt.Fprintf(os.Stderr, "Expected exactly one CSR, got %d\n", len(csrDatasBytes))
		os.Exit(1)
	}
	csrDataBytes := csrDatasBytes[0]

	csr, _, err := spec.Spec{}.ReadData(enc.NewBufferView(csrDataBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read CSR: %s\n", err)
		os.Exit(1)
	}

	notBefore := time.Now()
	notAfter := time.Now().AddDate(1, 0, 0)

	if t.Start != "now" {
		notBefore, err = time.Parse(TIME_LAYOUT, t.Start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse start time: %s\n", err)
			os.Exit(1)
		}
	}
	if t.End != "now + 1 year" {
		notAfter, err = time.Parse(TIME_LAYOUT, t.End)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse end time: %s\n", err)
			os.Exit(1)
		}
	}

	// TODO: set description
	certWire, err := security.SignCert(security.SignCertArgs{
		Signer:    signer,
		Data:      csr,
		IssuerId:  enc.NewGenericComponent(t.Issuer),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign certificate: %s\n", err)
		os.Exit(1)
	}

	pem, err := security.PemEncode(certWire.Join())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to PEM encode certificate: %s\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(pem)
}
