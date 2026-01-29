package sec

import (
	"github.com/spf13/cobra"
)

// (AI GENERATED DESCRIPTION): Creates and configures the `sec` command group, adding subcommands for key generation, certificate signing, keychain management, and PEM handling.
func CmdSec() *cobra.Command {
	cmd := &cobra.Command{
		GroupID: "sec",
		Use:     "sec",
		Short:   "NDN Security Utilities",
		Long: `NDN Security Utilities

Reference:
  https://github.com/named-data/ndnd/blob/main/docs/security-util.md`,
	}
	new(ToolKeygen).configure(cmd)
	new(ToolSignCert).configure(cmd)
	new(ToolKeychain).configure(cmd)
	new(ToolPem).configure(cmd)
	return cmd
}
