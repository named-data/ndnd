package sec

import (
	"fmt"
	"io"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/spf13/cobra"
)

type ToolKeychain struct{}

// (AI GENERATED DESCRIPTION): Registers the keychain‑management subcommands (key-list, key-import, key-export) and groups them under the “keychain” command group in the CLI.
func (t *ToolKeychain) configure(cmd *cobra.Command) {
	cmd.AddGroup(&cobra.Group{
		ID:    "keychain",
		Title: "Keychain Management",
	})

	cmd.AddCommand(&cobra.Command{
		GroupID: "keychain",
		Use:     "key-list KEYCHAIN-URI",
		Short:   "List keys in a keychain",
		Run:     t.List,
		Args:    cobra.ExactArgs(1),
		Example: `  ndnd sec key-list dir:///safe/keys`,
	})

	cmd.AddCommand(&cobra.Command{
		GroupID: "keychain",
		Use:     "key-import KEYCHAIN-URI",
		Short:   "Import keys or certs to a keychain",
		Long: `Import keys or certs to a keychain.

Expects one (TLV) or more (PEM) keys or certificates on stdin
and inserts them into the specified keychain.`,
		Args:    cobra.ExactArgs(1),
		Example: `  ndnd sec key-import dir:///safe/keys < alice.key`,
		Run:     t.Import,
	})

	cmd.AddCommand(&cobra.Command{
		GroupID: "keychain",
		Use:     "key-delete KEYCHAIN-URI KEY-NAME",
		Short:   "Delete a key and its certificates from a keychain",
		Args:    cobra.ExactArgs(2),
		Example: `  ndnd sec key-delete dir:///safe/keys /alice/KEY/%DE%AD%BE%EF`,
		Run:     t.DeleteKey,
	})

	cmd.AddCommand(&cobra.Command{
		GroupID: "keychain",
		Use:     "cert-delete KEYCHAIN-URI CERT-NAME",
		Short:   "Delete a certificate from a keychain",
		Args:    cobra.ExactArgs(2),
		Example: `  ndnd sec cert-delete dir:///safe/keys /alice/KEY/%DE%AD%BE%EF/%C0%DE%BE%EF/v=1`,
		Run:     t.DeleteCert,
	})

	cmd.AddCommand(&cobra.Command{
		GroupID: "keychain",
		Use:     "key-export KEYCHAIN-URI KEY-NAME",
		Short:   "Export a key from a keychain",
		Long: `Export the specified key from a keychain.
If no KEY is specified, name will be treated as an identity
and the default key of the identity will be exported.`,
		Args:    cobra.ExactArgs(2),
		Example: `  ndnd sec key-export dir:///safe/keys /alice`,
		Run:     t.Export,
	})
}

// (AI GENERATED DESCRIPTION): Lists all identities and their keys in the keychain at the given path, printing each identity name followed by the names of its keys.
func (*ToolKeychain) List(_ *cobra.Command, args []string) {
	kc, err := keychain.NewKeyChain(args[0], storage.NewMemoryStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open keychain: %s\n", err)
		os.Exit(1)
		return
	}

	for _, id := range kc.Identities() {
		fmt.Printf("%s\n", id.Name())
		for _, key := range id.Keys() {
			fmt.Printf("==> %s\n", key.KeyName())
		}
	}
}

// (AI GENERATED DESCRIPTION): Imports keychain entries from standard input into the keychain named by the first argument, storing them in a memory-based keychain.
func (*ToolKeychain) Import(_ *cobra.Command, args []string) {
	kc, err := keychain.NewKeyChain(args[0], storage.NewMemoryStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open keychain: %s\n", err)
		os.Exit(1)
		return
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read input: %s\n", err)
		os.Exit(1)
		return
	}

	err = keychain.InsertFile(kc, input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to insert keychain entries: %s\n", err)
		os.Exit(1)
		return
	}
}

// (AI GENERATED DESCRIPTION): Exports a specified key (or an identity’s default key) from a keychain, PEM‑encodes its secret key, and writes it to standard output.
func (*ToolKeychain) Export(_ *cobra.Command, args []string) {
	name, err := enc.NameFromStr(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid key name: %s\n", args[1])
		os.Exit(1)
		return
	}

	kc, err := keychain.NewKeyChain(args[0], storage.NewMemoryStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open keychain: %s\n", err)
		os.Exit(1)
		return
	}

	keyName := name
	id, err := security.GetIdentityFromKeyName(name)
	if err != nil { // not a key name
		id = name
		keyName = nil
	}

	idObj := kc.IdentityByName(id)
	if idObj == nil {
		fmt.Fprintf(os.Stderr, "Identity not found: %s\n", id)
		os.Exit(1)
		return
	}

	var signer ndn.Signer
	if keyName == nil {
		if len(idObj.Keys()) > 0 {
			signer = idObj.Keys()[0].Signer()
		}
	} else {
		for _, key := range idObj.Keys() {
			if key.KeyName().Equal(keyName) {
				signer = key.Signer()
				break
			}
		}
	}
	if signer == nil {
		fmt.Fprintf(os.Stderr, "Key not found: %s\n", keyName)
		os.Exit(1)
		return
	}

	secret, err := sig.MarshalSecret(signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode secret key: %s\n", err)
		os.Exit(1)
		return
	}

	out, err := security.PemEncode(secret.Join())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to convert secret key to text: %s\n", err)
		os.Exit(1)
		return
	}

	os.Stdout.Write(out)
}

// DeleteKey removes a key and its certificates from the keychain.
func (*ToolKeychain) DeleteKey(_ *cobra.Command, args []string) {
	name, err := enc.NameFromStr(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid key name: %s\n", args[1])
		os.Exit(1)
		return
	}

	kc, err := keychain.NewKeyChain(args[0], storage.NewMemoryStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open keychain: %s\n", err)
		os.Exit(1)
		return
	}

	if err := kc.DeleteKey(name); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to delete key: %s\n", err)
		os.Exit(1)
	}
}

// DeleteCert removes a certificate from the keychain.
func (*ToolKeychain) DeleteCert(_ *cobra.Command, args []string) {
	name, err := enc.NameFromStr(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid certificate name: %s\n", args[1])
		os.Exit(1)
		return
	}

	kc, err := keychain.NewKeyChain(args[0], storage.NewMemoryStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open keychain: %s\n", err)
		os.Exit(1)
		return
	}

	if err := kc.DeleteCert(name); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to delete certificate: %s\n", err)
		os.Exit(1)
	}
}
